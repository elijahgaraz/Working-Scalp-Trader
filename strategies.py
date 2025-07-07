from abc import ABC, abstractmethod
from typing import Any, List, Sequence, Dict
from statistics import mean


def _sma(values: Sequence[float], window: int) -> float:
    return mean(values) if len(values) < window else mean(values[-window:])


import pandas as pd
# Assuming indicators.py is in the same directory or PYTHONPATH
from indicators import calculate_ema, calculate_atr
# Removed unused _sma and mean from statistics as SafeStrategy will use indicators.py

class Strategy(ABC):
    """Abstract base class for trading strategies."""
    NAME = "BaseStrategy" # Default name

    @abstractmethod
    def decide(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Makes a trading decision based on the provided data.
        Args:
            data: A dictionary containing market data, account info, etc.
                  Expected keys for SafeStrategy:
                    'ohlc_1m': pd.DataFrame,
                    'ohlc_15s': pd.DataFrame (currently not used by SafeStrategy logic, current_price_tick is used instead for 15s price point)
                    'current_equity': float | None,
                    'pip_position': int | None,
                    'current_price_tick': float | None
        Returns:
            A dictionary like:
            {'action': 'buy'|'sell'|'hold',
             'sl_offset': float | None (price offset for SL if action is buy/sell),
             'tp_offset': float | None (price offset for TP if action is buy/sell),
             'comment': str}
        """
        ...


class SafeStrategy(Strategy):
    """Safe (Low-Risk) Trend-Following Scalper"""
    NAME = "Safe (Low-Risk) Trend-Following Scalper"
    EMA1_PERIOD_1M = 20
    EMA2_PERIOD_1M = 50
    ATR_PERIOD_1M = 14
    ATR_SL_MULTIPLIER = 0.5
    ATR_TP_MULTIPLIER = 1.0
    # Minimum bars needed for longest EMA + ATR + a few for stability in calculations
    MIN_BARS_1M = EMA2_PERIOD_1M + ATR_PERIOD_1M + 5

    # __init__ is no longer needed if parameters are class constants
    # def __init__(self, short_window: int = 20, long_window: int = 50):
    #     self.short_window = short_window
    #     self.long_window = long_window

    def decide(self, data: Dict[str, Any]) -> Dict[str, Any]:
        action = 'hold'
        sl_offset = None
        tp_offset = None
        comment = f"{self.NAME}: Initializing"

        ohlc_1m = data.get('ohlc_1m')
        current_price_tick = data.get('current_price_tick')
        # current_equity = data.get('current_equity') # For position sizing later
        # pip_position = data.get('pip_position') # For SL/TP in pips later

        if not isinstance(ohlc_1m, pd.DataFrame) or ohlc_1m.empty or len(ohlc_1m) < self.MIN_BARS_1M:
            comment = f"{self.NAME}: Insufficient 1m OHLC data (bars: {len(ohlc_1m) if isinstance(ohlc_1m, pd.DataFrame) else 0}/{self.MIN_BARS_1M})"
            return {'action': 'hold', 'comment': comment, 'sl_offset': None, 'tp_offset': None}

        if current_price_tick is None:
            comment = f"{self.NAME}: Current tick price unavailable for 15s confirmation"
            return {'action': 'hold', 'comment': comment, 'sl_offset': None, 'tp_offset': None}

        # Ensure required columns are present and lowercase
        required_cols_1m = ['open', 'high', 'low', 'close']
        if not all(col in ohlc_1m.columns for col in required_cols_1m):
             comment = f"{self.NAME}: 1m OHLC data missing one or more required columns (open, high, low, close)"
             return {'action': 'hold', 'comment': comment, 'sl_offset': None, 'tp_offset': None}

        # 1. Calculate 1-Minute Indicators
        try:
            # Ensure source_col exists, use .get() with default or ensure it's there
            ema1_1m = calculate_ema(ohlc_1m, length=self.EMA1_PERIOD_1M, source_col='close')
            ema2_1m = calculate_ema(ohlc_1m, length=self.EMA2_PERIOD_1M, source_col='close')
            atr_1m = calculate_atr(ohlc_1m, length=self.ATR_PERIOD_1M) # calculate_atr expects lowercase HLC
        except Exception as e:
            comment = f"{self.NAME}: Error calculating 1m indicators: {e}"
            return {'action': 'hold', 'comment': comment, 'sl_offset': None, 'tp_offset': None}

        if ema1_1m.empty or ema2_1m.empty or atr_1m.empty or \
           ema1_1m.isnull().all() or ema2_1m.isnull().all() or atr_1m.isnull().all() or \
           len(ema1_1m) < 2 or len(ema2_1m) < 2: # Need at least 2 for prev_ema comparison
            comment = f"{self.NAME}: Not enough data returned from 1m indicator calculations"
            return {'action': 'hold', 'comment': comment, 'sl_offset': None, 'tp_offset': None}

        last_ema1 = ema1_1m.iloc[-1]
        prev_ema1 = ema1_1m.iloc[-2]
        last_ema2 = ema2_1m.iloc[-1]
        prev_ema2 = ema2_1m.iloc[-2]
        last_atr = atr_1m.iloc[-1]

        if pd.isna(last_ema1) or pd.isna(prev_ema1) or pd.isna(last_ema2) or pd.isna(prev_ema2) or pd.isna(last_atr):
            comment = f"{self.NAME}: NaN values in latest indicators."
            return {'action': 'hold', 'comment': comment, 'sl_offset': None, 'tp_offset': None}

        current_price_1m_close = ohlc_1m['close'].iloc[-1]

        # 2. Entry Logic (1-minute chart)
        long_bias = current_price_1m_close > last_ema2
        short_bias = current_price_1m_close < last_ema2

        long_crossover = (last_ema1 > last_ema2) and (prev_ema1 <= prev_ema2)
        short_crossover = (last_ema1 < last_ema2) and (prev_ema1 >= prev_ema2)

        # 3. Confirmation Logic (using current_price_tick against 1-min EMA2)
        confirm_long = current_price_tick > last_ema2
        confirm_short = current_price_tick < last_ema2

        # Debugging log preparation
        # comment = (f"{self.NAME} Eval: P1m={current_price_1m_close:.5f}, EMA1={last_ema1:.5f}({prev_ema1:.5f}), EMA2={last_ema2:.5f}({prev_ema2:.5f}), "
        #            f"ATR={last_atr:.5f}, Ptick={current_price_tick:.5f}. "
        #            f"Bias(L/S):{long_bias}/{short_bias}, XOver(L/S):{long_crossover}/{short_crossover}, Conf(L/S):{confirm_long}/{confirm_short}")


        if long_bias and long_crossover and confirm_long:
            action = 'buy'
            sl_offset = last_atr * self.ATR_SL_MULTIPLIER
            tp_offset = last_atr * self.ATR_TP_MULTIPLIER
            comment = f"{self.NAME} Signal: BUY. EMA Cross & Price > EMA{self.EMA2_PERIOD_1M}. 15s Confirm Tick > EMA{self.EMA2_PERIOD_1M}."
        elif short_bias and short_crossover and confirm_short:
            action = 'sell'
            sl_offset = last_atr * self.ATR_SL_MULTIPLIER
            tp_offset = last_atr * self.ATR_TP_MULTIPLIER
            comment = f"{self.NAME} Signal: SELL. EMA Cross & Price < EMA{self.EMA2_PERIOD_1M}. 15s Confirm Tick < EMA{self.EMA2_PERIOD_1M}."
        else:
            action = 'hold' # Explicitly hold
            comment = f"{self.NAME} No Signal: LB={long_bias},SB={short_bias},LC={long_crossover},SC={short_crossover},CL={confirm_long},CS={confirm_short}"


        return {'action': action, 'sl_offset': sl_offset, 'tp_offset': tp_offset, 'comment': comment}


class ModerateStrategy(Strategy):
    NAME = "Moderate Breakout Scalper"
    def decide(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # print(f"{self.NAME}.decide() called, data keys:", data.keys() if data else "None")
        return {'action': 'hold', 'comment': f'{self.NAME} not implemented', 'sl_offset': None, 'tp_offset': None}

class AggressiveStrategy(Strategy):
    NAME = "Aggressive Tick-Scalper"
    def decide(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # print(f"{self.NAME}.decide() called, data keys:", data.keys() if data else "None")
        return {'action': 'hold', 'comment': f'{self.NAME} not implemented', 'sl_offset': None, 'tp_offset': None}

class MomentumStrategy(Strategy):
    NAME = "Momentum Fade Scalper" # This was named MomentumStrategy, but description suggests Momentum Fade
    def decide(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # print(f"{self.NAME}.decide() called, data keys:", data.keys() if data else "None")
        return {'action': 'hold', 'comment': f'{self.NAME} not implemented', 'sl_offset': None, 'tp_offset': None}

class MeanReversionStrategy(Strategy):
    NAME = "Mean-Reversion Scalper"
    def decide(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # print(f"{self.NAME}.decide() called, data keys:", data.keys() if data else "None")
        return {'action': 'hold', 'comment': f'{self.NAME} not implemented', 'sl_offset': None, 'tp_offset': None}
