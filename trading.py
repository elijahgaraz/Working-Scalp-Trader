from __future__ import annotations
import threading
import webbrowser
import requests
import random
import time
from typing import List, Any, Optional, Tuple, Dict
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
# import socketserver # Not directly used with basic HTTPServer in a thread
import queue
import sys
import traceback
import pandas as pd
from datetime import datetime, timezone

# Conditional import for Twisted reactor for GUI integration
_reactor_installed = False
try:
    from twisted.internet import reactor, tksupport
    _reactor_installed = True
except ImportError:
    print("Twisted reactor or GUI support not found. GUI integration with Twisted might require manual setup.")


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, auth_code_queue: queue.Queue, **kwargs):
        self.auth_code_queue = auth_code_queue
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path == "/callback":
            query_components = urllib.parse.parse_qs(parsed_path.query)
            auth_code = query_components.get("code", [None])[0]

            if auth_code:
                self.auth_code_queue.put(auth_code)
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Authentication Successful!</h1>")
                self.wfile.write(b"<p>You can close this browser tab and return to the application.</p></body></html>")
                print(f"OAuth callback handled, code extracted: {auth_code[:20]}...")
            else:
                self.send_response(400)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Authentication Failed</h1><p>No authorization code found in callback.</p></body></html>")
                print("OAuth callback error: No authorization code found.")
                self.auth_code_queue.put(None) # Signal failure or no code
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Not Found</h1></body></html>")

    def log_message(self, format, *args):
        # Suppress most log messages from the HTTP server for cleaner console
        # You might want to enable some for debugging.
        # Example: only log errors or specific messages
        if "400" in args[0] or "404" in args[0] or "code 200" in args[0]: # Log errors and successful callback
             super().log_message(format, *args)
        # else:
        #    pass


import json # For token persistence

# Imports from ctrader-open-api
try:
    from ctrader_open_api import Client, TcpProtocol, EndPoints, Protobuf
    from ctrader_open_api.messages.OpenApiCommonMessages_pb2 import (
        ProtoHeartbeatEvent,
        ProtoErrorRes,
        ProtoMessage
        # ProtoPayloadType / ProtoOAPayloadType not here
    )
    from ctrader_open_api.messages.OpenApiMessages_pb2 import (
        ProtoOAApplicationAuthReq, ProtoOAApplicationAuthRes,
        ProtoOAAccountAuthReq, ProtoOAAccountAuthRes,
        ProtoOAGetAccountListByAccessTokenReq, ProtoOAGetAccountListByAccessTokenRes,
        ProtoOATraderReq, ProtoOATraderRes,
        ProtoOASubscribeSpotsReq, ProtoOASubscribeSpotsRes,
        ProtoOASpotEvent, ProtoOATraderUpdatedEvent,
        ProtoOANewOrderReq, ProtoOAExecutionEvent,
        ProtoOAErrorRes,
        # Specific message types for deserialization
        ProtoOAGetCtidProfileByTokenRes,
        ProtoOAGetCtidProfileByTokenReq,
        ProtoOASymbolsListReq, ProtoOASymbolsListRes, # For fetching symbol list (light symbols)
        ProtoOASymbolByIdReq, ProtoOASymbolByIdRes    # For fetching full symbol details
    )
    # ProtoOALightSymbol is implicitly used by ProtoOASymbolsListRes
    # ProtoOASymbol is used by ProtoOASymbolByIdRes and for our symbol_details_map value type
    from ctrader_open_api.messages.OpenApiModelMessages_pb2 import ProtoOATrader, ProtoOASymbol
    USE_OPENAPI_LIB = True
except ImportError as e:
    print(f"ctrader-open-api import failed ({e}); running in mock mode.")
    USE_OPENAPI_LIB = False

TOKEN_FILE_PATH = "tokens.json"

class Trader:
    def __init__(self, settings, history_size: int = 100):
        """
        Initializes the Trader.

        Args:
            settings: The application settings object.
            history_size: The maximum size of the price history to maintain.
        """
        self.settings = settings
        self.is_connected: bool = False
        self._is_client_connected: bool = False
        self._last_error: str = ""
        self.price_history: List[float] = [] # Stores recent bid prices for the default symbol (tick data)
        self.history_size = history_size # Max length for self.price_history

        # OHLC Data Storage for default symbol
        self.timeframes_seconds = {
            '15s': 15,
            '1m': 60,
            '5m': 300
        }
        self.current_bars = {} # Stores the currently forming bar for each timeframe
        self.ohlc_history = {} # Stores history of completed bars for each timeframe
        self.max_ohlc_history_len = 200 # Max number of OHLC bars to keep per timeframe

        for tf_str in self.timeframes_seconds.keys():
            self.current_bars[tf_str] = {
                'timestamp': None, # Start time of the bar (datetime object)
                'open': None,
                'high': None,
                'low': None,
                'close': None,
                'volume': 0 # Using tick count as volume for now
            }
            self.ohlc_history[tf_str] = pd.DataFrame(
                columns=['timestamp', 'open', 'high', 'low', 'close', 'volume']
            )


        # Initialize token fields before loading
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: Optional[float] = None
        self._load_tokens_from_file() # Load tokens on initialization

        # Account details
        self.ctid_trader_account_id: Optional[int] = settings.openapi.default_ctid_trader_account_id
        self.account_id: Optional[str] = None # Will be string representation of ctidTraderAccountId
        self.balance: Optional[float] = None
        self.equity: Optional[float] = None
        self.currency: Optional[str] = None
        self.used_margin: Optional[float] = None # For margin used

        # Symbol data
        self.symbols_map: Dict[str, int] = {} # Map from symbol name to symbolId
        self.symbol_details_map: Dict[int, Any] = {} # Map from symbolId to ProtoOASymbol
        self.default_symbol_id: Optional[int] = None # Symbol ID for the default_symbol from settings
        self.subscribed_spot_symbol_ids: set[int] = set()


        self._client: Optional[Client] = None
        self._message_id_counter: int = 1
        self._reactor_thread: Optional[threading.Thread] = None
        self._auth_code: Optional[str] = None # To store the auth code from OAuth flow
        self._account_auth_initiated: bool = False # Flag to prevent duplicate account auth attempts

        if USE_OPENAPI_LIB:
            host = (
                EndPoints.PROTOBUF_LIVE_HOST
                if settings.openapi.host_type == "live"
                else EndPoints.PROTOBUF_DEMO_HOST
            )
            port = EndPoints.PROTOBUF_PORT
            self._client = Client(host, port, TcpProtocol)
            self._client.setConnectedCallback(self._on_client_connected)
            self._client.setDisconnectedCallback(self._on_client_disconnected)
            self._client.setMessageReceivedCallback(self._on_message_received)
        else:
            print("Trader initialized in MOCK mode.")

        self._auth_code_queue = queue.Queue() # Queue to pass auth_code from HTTP server thread
        self._http_server_thread: Optional[threading.Thread] = None
        self._http_server: Optional[HTTPServer] = None

    def _save_tokens_to_file(self):
        """Saves the current OAuth access token, refresh token, and expiry time to TOKEN_FILE_PATH."""
        tokens = {
            "access_token": self._access_token,
            "refresh_token": self._refresh_token,
            "token_expires_at": self._token_expires_at,
        }
        try:
            with open(TOKEN_FILE_PATH, "w") as f:
                json.dump(tokens, f)
            print(f"Tokens saved to {TOKEN_FILE_PATH}")
        except IOError as e:
            print(f"Error saving tokens to {TOKEN_FILE_PATH}: {e}")

    def _load_tokens_from_file(self):
        """Loads OAuth tokens from a local file."""
        try:
            with open(TOKEN_FILE_PATH, "r") as f:
                tokens = json.load(f)
            self._access_token = tokens.get("access_token")
            self._refresh_token = tokens.get("refresh_token")
            self._token_expires_at = tokens.get("token_expires_at")
            if self._access_token:
                print(f"Tokens loaded from {TOKEN_FILE_PATH}. Access token: {self._access_token[:20]}...")
            else:
                print(f"{TOKEN_FILE_PATH} not found or no access token in it. Will need OAuth.")
        except FileNotFoundError:
            print(f"Token file {TOKEN_FILE_PATH} not found. New OAuth flow will be required.")
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error loading tokens from {TOKEN_FILE_PATH}: {e}. Will need OAuth flow.")
            # In case of corrupted file, good to try to remove it or back it up
            try:
                import os
                os.remove(TOKEN_FILE_PATH)
                print(f"Removed corrupted token file: {TOKEN_FILE_PATH}")
            except OSError as rm_err:
                print(f"Error removing corrupted token file: {rm_err}")

    def _next_message_id(self) -> str:
        mid = str(self._message_id_counter)
        self._message_id_counter += 1
        return mid

    # Twisted callbacks
    def _on_client_connected(self, client: Client) -> None:
        print("OpenAPI Client Connected.")
        self._is_client_connected = True
        self._last_error = ""
        req = ProtoOAApplicationAuthReq()
        req.clientId = self.settings.openapi.client_id or ""
        req.clientSecret = self.settings.openapi.client_secret or ""
        if not req.clientId or not req.clientSecret:
            print("Missing OpenAPI credentials.")
            client.stopService()
            return
        print(f"Sending ProtoOAApplicationAuthReq: {req}")
        d = client.send(req)
        d.addCallbacks(self._handle_app_auth_response, self._handle_send_error)

    def _on_client_disconnected(self, client: Client, reason: Any) -> None:
        print(f"OpenAPI Client Disconnected: {reason}")
        self.is_connected = False
        self._is_client_connected = False
        self._account_auth_initiated = False # Reset flag

    def _on_message_received(self, client: Client, message: Any) -> None:
        print(f"Original message received (type: {type(message)}): {message}")

        # Attempt to extract and deserialize using Protobuf.extract
        try:
            actual_message = Protobuf.extract(message)
            print(f"Message extracted via Protobuf.extract (type: {type(actual_message)}): {actual_message}")
        except Exception as e:
            print(f"Error using Protobuf.extract: {e}. Falling back to manual deserialization if possible.")
            actual_message = message # Fallback to original message for manual processing attempt
            # Log additional details about the original message if it's a ProtoMessage
            if isinstance(message, ProtoMessage):
                 print(f"  Fallback: Original ProtoMessage PayloadType: {message.payloadType}, Payload Bytes: {message.payload[:64]}...") # Log first 64 bytes

        # If Protobuf.extract returned the original ProtoMessage wrapper, it means it couldn't deserialize it.
        # Or if an error occurred and we fell back.
        # We can attempt manual deserialization as before, but it's better if Protobuf.extract handles it.
        # For now, the dispatch logic below will use the result of Protobuf.extract.
        # If actual_message is still ProtoMessage, the specific isinstance checks will fail,
        # which is the correct behavior if it couldn't be properly deserialized.

        # We need to get payload_type for logging in case it's an unhandled ProtoMessage
        payload_type = 0
        if isinstance(actual_message, ProtoMessage): # If still a wrapper after extract attempt
            payload_type = actual_message.payloadType
            print(f"  Protobuf.extract did not fully deserialize. Message is still ProtoMessage wrapper with PayloadType: {payload_type}")
        elif isinstance(message, ProtoMessage) and actual_message is message: # Fallback case where actual_message was reset to original
            payload_type = message.payloadType
        # Ensure payload_type is defined for the final log message if it's an unhandled ProtoMessage
        final_payload_type_for_log = payload_type if isinstance(actual_message, ProtoMessage) else getattr(actual_message, 'payloadType', 'N/A')


        # Dispatch by type using the (potentially deserialized) actual_message
        if isinstance(actual_message, ProtoOAApplicationAuthRes):
            print("  Dispatching to _handle_app_auth_response")
            self._handle_app_auth_response(actual_message)
        elif isinstance(actual_message, ProtoOAAccountAuthRes):
            print("  Dispatching to _handle_account_auth_response")
            self._handle_account_auth_response(actual_message)
        elif isinstance(actual_message, ProtoOAGetCtidProfileByTokenRes):
            print("  Dispatching to _handle_get_ctid_profile_response")
            self._handle_get_ctid_profile_response(actual_message)
        elif isinstance(actual_message, ProtoOAGetAccountListByAccessTokenRes):
            print("  Dispatching to _handle_get_account_list_response")
            self._handle_get_account_list_response(actual_message)
        elif isinstance(actual_message, ProtoOASymbolsListRes):
            print("  Dispatching to _handle_symbols_list_response")
            self._handle_symbols_list_response(actual_message)
        elif isinstance(actual_message, ProtoOASymbolByIdRes):
            print("  Dispatching to _handle_symbol_details_response")
            self._handle_symbol_details_response(actual_message)
        elif isinstance(actual_message, ProtoOASubscribeSpotsRes):
            # This is usually handled by the callback in _send_subscribe_spots_request directly,
            # but good to have a dispatch log if it comes through _on_message_received.
            print("  Received ProtoOASubscribeSpotsRes (typically handled by send callback).")
            # self._handle_subscribe_spots_response(actual_message, []) # Might need context if called here
        elif isinstance(actual_message, ProtoOATraderRes):
            print("  Dispatching to _handle_trader_response")
            self._handle_trader_response(actual_message)
        elif isinstance(actual_message, ProtoOATraderUpdatedEvent):
            print("  Dispatching to _handle_trader_updated_event")
            self._handle_trader_updated_event(actual_message)
        elif isinstance(actual_message, ProtoOASpotEvent):
            self._handle_spot_event(actual_message) # Potentially noisy
            # print("  Received ProtoOASpotEvent (handler commented out).")
        elif isinstance(actual_message, ProtoOAExecutionEvent):
            # self._handle_execution_event(actual_message) # Potentially noisy
             print("  Received ProtoOAExecutionEvent (handler commented out).")
        elif isinstance(actual_message, ProtoHeartbeatEvent):
            print("  Received heartbeat.")
        elif isinstance(actual_message, ProtoOAErrorRes): # Specific OA error
            print(f"  Dispatching to ProtoOAErrorRes handler. Error code: {actual_message.errorCode}, Description: {actual_message.description}")
            self._last_error = f"{actual_message.errorCode}: {actual_message.description}"
        elif isinstance(actual_message, ProtoErrorRes): # Common error
            print(f"  Dispatching to ProtoErrorRes (common) handler. Error code: {actual_message.errorCode}, Description: {actual_message.description}")
            self._last_error = f"Common Error {actual_message.errorCode}: {actual_message.description}"
        # Check if it's still the ProtoMessage wrapper (meaning Protobuf.extract didn't deserialize it further)
        elif isinstance(actual_message, ProtoMessage): # Covers actual_message is message (if message was ProtoMessage)
                                                       # and actual_message is the result of extract but still a wrapper.
            print(f"  ProtoMessage with PayloadType {actual_message.payloadType} was not handled by specific type checks.")
        elif actual_message is message and not isinstance(message, ProtoMessage): # Original message was not ProtoMessage and not handled
             print(f"  Unhandled non-ProtoMessage type in _on_message_received: {type(actual_message)}")
        else: # Should ideally not be reached if all cases are handled
            print(f"  Message of type {type(actual_message)} (PayloadType {final_payload_type_for_log}) fell through all handlers.")

    # Handlers
    def _handle_app_auth_response(self, response: ProtoOAApplicationAuthRes) -> None:
        print("ApplicationAuth response received.")

        if self._account_auth_initiated:
            print("Account authentication process already initiated, skipping duplicate _handle_app_auth_response.")
            return

        # The access token from ProtoOAApplicationAuthRes is for the application's session.
        # We have a user-specific OAuth access token in self._access_token (if OAuth flow completed).
        # We should not overwrite self._access_token here if it was set by OAuth.
        # For ProtoOAAccountAuthReq, we must use the user's OAuth token.

        # Let's see if the response contains an access token, though we might not use it directly
        # if our main OAuth token is already present.
        app_session_token = getattr(response, 'accessToken', None)
        if app_session_token:
            print(f"ApplicationAuthRes provided an app session token: {app_session_token[:20]}...")
            # If self._access_token (OAuth user token) is NOT set,
            # this could be a fallback or an alternative flow not fully explored.
            # For now, we prioritize the OAuth token set by exchange_code_for_token.
            if not self._access_token:
                print("Warning: OAuth access token not found, but AppAuthRes provided one. This scenario needs review.")
                # self._access_token = app_session_token # Potentially use if no OAuth token? Risky.

        if not self._access_token:
            self._last_error = "Critical: OAuth access token not available for subsequent account operations."
            print(self._last_error)
            # Potentially stop the client or signal a critical failure here
            if self._client:
                self._client.stopService()
            return

        # Proceed to account authentication or discovery, using the OAuth access token (self._access_token)
        if self.ctid_trader_account_id and self._access_token:
            # If a ctidTraderAccountId is known (e.g., from settings) and we have an OAuth access token,
            # proceed directly with ProtoOAAccountAuthReq as per standard Spotware flow.
            print(f"Known ctidTraderAccountId: {self.ctid_trader_account_id}. Attempting ProtoOAAccountAuthReq.")
            self._account_auth_initiated = True # Set flag before sending
            self._send_account_auth_request(self.ctid_trader_account_id)
        elif self._access_token:
            # If ctidTraderAccountId is not known, but we have an access token,
            # first try to get the account list associated with this token.
            # ProtoOAGetAccountListByAccessTokenReq is preferred over ProtoOAGetCtidProfileByTokenReq
            # if the goal is to find trading accounts. Profile is more about user details.
            print("No default ctidTraderAccountId. Attempting to get account list by access token.")
            self._account_auth_initiated = True # Set flag before sending
            self._send_get_account_list_request()
        else:
            # This case should ideally be prevented by earlier checks in the connect() flow.
            self._last_error = "Critical: Cannot proceed with account auth/discovery. Missing ctidTraderAccountId or access token after app auth."
            print(self._last_error)
            if self._client:
                self._client.stopService()


    def _handle_get_ctid_profile_response(self, response: ProtoOAGetCtidProfileByTokenRes) -> None:
        """
        Handles the response from a ProtoOAGetCtidProfileByTokenReq.
        Its primary role is to provide user profile information.
        It might also list associated ctidTraderAccountIds, which can be used if an ID isn't already known.
        This handler does NOT set self.is_connected; connection is confirmed by ProtoOAAccountAuthRes.
        """
        print(f"Received ProtoOAGetCtidProfileByTokenRes. Content: {response}")

        # Example of how you might use profile data if needed:
        # if hasattr(response, 'profile') and response.profile:
        #     print(f"  User Profile Nickname: {response.profile.nickname}")

        # Check if the response contains ctidTraderAccount details.
        # According to some message definitions, ProtoOAGetCtidProfileByTokenRes
        # might not directly list accounts. ProtoOAGetAccountListByAccessTokenRes is for that.
        # However, if it *does* provide an account ID and we don't have one, we could note it.
        # For now, this handler mainly logs. If a ctidTraderAccountId is needed and not present,
        # the flow should have gone through _send_get_account_list_request.

        # If, for some reason, this response is used to discover a ctidTraderAccountId:
        # found_ctid = None
        # if hasattr(response, 'ctidProfile') and hasattr(response.ctidProfile, 'ctidTraderId'): # Speculative
        #     found_ctid = response.ctidProfile.ctidTraderId
        #
        # if found_ctid and not self.ctid_trader_account_id:
        #     print(f"  Discovered ctidTraderAccountId from profile: {found_ctid}. Will attempt account auth.")
        #     self.ctid_trader_account_id = found_ctid
        #     self._send_account_auth_request(self.ctid_trader_account_id)
        # elif not self.ctid_trader_account_id:
        #     self._last_error = "Profile received, but no ctidTraderAccountId found to proceed with account auth."
        #     print(self._last_error)

        # This response does not confirm a live trading session for an account.
        # That's the role of ProtoOAAccountAuthRes.
        pass

    def _handle_subscribe_spots_response(self, response_wrapper: Any, subscribed_symbol_ids: List[int]) -> None:
        """Handles the response from a ProtoOASubscribeSpotsReq."""
        if isinstance(response_wrapper, ProtoMessage):
            actual_message = Protobuf.extract(response_wrapper)
            print(f"_handle_subscribe_spots_response: Extracted {type(actual_message)} from ProtoMessage wrapper.")
        else:
            actual_message = response_wrapper

        if not isinstance(actual_message, ProtoOASubscribeSpotsRes):
            print(f"_handle_subscribe_spots_response: Expected ProtoOASubscribeSpotsRes, got {type(actual_message)}. Message: {actual_message}")
            # Potentially set an error or log failure for specific symbols if the response structure allowed it.
            # For ProtoOASubscribeSpotsRes, it's usually an empty message on success.
            # Errors would typically come as ProtoOAErrorRes or via _handle_send_error.
            self._last_error = f"Spot subscription response was not ProtoOASubscribeSpotsRes for symbols {subscribed_symbol_ids}."
            return

        # ProtoOASubscribeSpotsRes is an empty message. Its reception confirms the subscription request was processed.
        # Actual spot data will come via ProtoOASpotEvent.
        print(f"Successfully processed spot subscription request for ctidTraderAccountId: {self.ctid_trader_account_id} and symbol IDs: {subscribed_symbol_ids}.")
        # No specific action needed here other than logging, errors are usually separate messages.

    def _send_get_symbol_details_request(self, symbol_ids: List[int]) -> None:
        """Sends a ProtoOASymbolByIdReq to get full details for specific symbol IDs."""
        if not self._ensure_valid_token():
            return
        if not self._client or not self._is_client_connected:
            self._last_error = "Cannot get symbol details: Client not connected."
            print(self._last_error)
            return
        if not self.ctid_trader_account_id: # ctidTraderAccountId is not part of ProtoOASymbolByIdReq
            pass # but good to ensure we have it generally for consistency
        if not symbol_ids:
            self._last_error = "Cannot get symbol details: No symbol_ids provided."
            print(self._last_error)
            return

        print(f"Requesting full symbol details for IDs: {symbol_ids}")
        req = ProtoOASymbolByIdReq()
        req.symbolId.extend(symbol_ids)
        if not self.ctid_trader_account_id:
            self._last_error = "Cannot get symbol details: ctidTraderAccountId is not set."
            print(self._last_error)
            return
        req.ctidTraderAccountId = self.ctid_trader_account_id

        print(f"Sending ProtoOASymbolByIdReq: {req}")
        try:
            d = self._client.send(req)
            # The callback will handle ProtoOASymbolByIdRes
            d.addCallbacks(self._handle_symbol_details_response, self._handle_send_error)
            print("Added callbacks to ProtoOASymbolByIdReq Deferred.")
        except Exception as e:
            print(f"Exception during _send_get_symbol_details_request send command: {e}")
            self._last_error = f"Exception sending symbol details request: {e}"

    def _send_get_symbols_list_request(self) -> None:
        """Sends a ProtoOASymbolsListReq to get all symbols for the authenticated account."""
        if not self._ensure_valid_token(): # Should not be strictly necessary if called after successful auth, but good practice
            return
        if not self._client or not self._is_client_connected:
            self._last_error = "Cannot get symbols list: Client not connected."
            print(self._last_error)
            return
        if not self.ctid_trader_account_id:
            self._last_error = "Cannot get symbols list: ctidTraderAccountId is not set."
            print(self._last_error)
            return

        print(f"Requesting symbols list for account {self.ctid_trader_account_id}")
        req = ProtoOASymbolsListReq()
        req.ctidTraderAccountId = self.ctid_trader_account_id
        # req.includeArchivedSymbols = False # Optional: to include archived symbols

        print(f"Sending ProtoOASymbolsListReq: {req}")
        try:
            d = self._client.send(req)
            d.addCallbacks(self._handle_symbols_list_response, self._handle_send_error)
            print("Added callbacks to ProtoOASymbolsListReq Deferred.")
        except Exception as e:
            print(f"Exception during _send_get_symbols_list_request send command: {e}")
            self._last_error = f"Exception sending symbols list request: {e}"

    def _handle_symbols_list_response(self, response_wrapper: Any) -> None:
        """Handles the response from a ProtoOASymbolsListReq."""
        if isinstance(response_wrapper, ProtoMessage):
            actual_message = Protobuf.extract(response_wrapper)
            print(f"_handle_symbols_list_response: Extracted {type(actual_message)} from ProtoMessage wrapper.")
        else:
            actual_message = response_wrapper

        if not isinstance(actual_message, ProtoOASymbolsListRes):
            print(f"_handle_symbols_list_response: Expected ProtoOASymbolsListRes, got {type(actual_message)}. Message: {actual_message}")
            self._last_error = "Symbols list response was not ProtoOASymbolsListRes."
            return

        print(f"Received ProtoOASymbolsListRes with {len(actual_message.symbol)} symbols.")
        self.symbols_map.clear()
        # self.symbol_details_map.clear() # Cleared by symbol_details_response if needed, or upon new full fetch
        self.default_symbol_id = None

        # The field in ProtoOASymbolsListRes is typically 'symbol' but contains ProtoOALightSymbol objects.
        # If the field name is different (e.g., 'lightSymbol'), this loop needs adjustment.
        # Assuming it's 'symbol' based on typical Protobuf generation.
        symbols_field = getattr(actual_message, 'symbol', []) # Default to empty list if field not found

        print(f"Received ProtoOASymbolsListRes with {len(symbols_field)} light symbols.")


        for light_symbol_proto in symbols_field: # These are ProtoOALightSymbol
            self.symbols_map[light_symbol_proto.symbolName] = light_symbol_proto.symbolId
            # print(f"  Light Symbol: {light_symbol_proto.symbolName}, ID: {light_symbol_proto.symbolId}")

            if light_symbol_proto.symbolName == self.settings.general.default_symbol:
                self.default_symbol_id = light_symbol_proto.symbolId
                print(f"Found default_symbol: '{self.settings.general.default_symbol}' with ID: {self.default_symbol_id} (Light symbol details). Requesting full details.")

        if self.default_symbol_id is not None:
            # Now that we have the ID, request full details for the default symbol
            self._send_get_symbol_details_request([self.default_symbol_id])
        else:
            print(f"Warning: Default symbol '{self.settings.general.default_symbol}' not found in symbols list for account {self.ctid_trader_account_id}.")
            self._last_error = f"Default symbol '{self.settings.general.default_symbol}' not found."

    def _handle_symbol_details_response(self, response_wrapper: Any) -> None:
        """Handles the response from a ProtoOASymbolByIdReq, containing full symbol details."""
        if isinstance(response_wrapper, ProtoMessage):
            actual_message = Protobuf.extract(response_wrapper)
            print(f"_handle_symbol_details_response: Extracted {type(actual_message)} from ProtoMessage wrapper.")
        else:
            actual_message = response_wrapper

        if not isinstance(actual_message, ProtoOASymbolByIdRes):
            print(f"_handle_symbol_details_response: Expected ProtoOASymbolByIdRes, got {type(actual_message)}. Message: {actual_message}")
            self._last_error = "Symbol details response was not ProtoOASymbolByIdRes."
            # Potentially try to re-request or handle error for specific symbols if needed.
            return

        print(f"Received ProtoOASymbolByIdRes with details for {len(actual_message.symbol)} symbol(s).")

        for detailed_symbol_proto in actual_message.symbol: # These are full ProtoOASymbol objects
            # ProtoOASymbol does not have symbolName, get it from symbols_map
            symbol_name_for_logging = "Unknown"
            for name, id_val in self.symbols_map.items():
                if id_val == detailed_symbol_proto.symbolId:
                    symbol_name_for_logging = name
                    break

            self.symbol_details_map[detailed_symbol_proto.symbolId] = detailed_symbol_proto
            print(f"  Stored full details for Symbol ID: {detailed_symbol_proto.symbolId} ({symbol_name_for_logging}), Digits: {detailed_symbol_proto.digits}, PipPosition: {detailed_symbol_proto.pipPosition}")

        # After updating the details map, check if we have details for the default symbol
        # and if so, proceed to subscribe for its spot prices.
        if self.default_symbol_id is not None and self.default_symbol_id in self.symbol_details_map:
            # Get the default symbol's name from symbols_map for logging
            default_symbol_name_for_logging = "Unknown"
            for name, id_val in self.symbols_map.items():
                if id_val == self.default_symbol_id:
                    default_symbol_name_for_logging = name
                    break

            print(f"Full details for default symbol '{default_symbol_name_for_logging}' (ID: {self.default_symbol_id}) received. Subscribing to spots.")

            # Ensure ctidTraderAccountId is available before subscribing
            if self.ctid_trader_account_id is not None:
                self._send_subscribe_spots_request(self.ctid_trader_account_id, [self.default_symbol_id])
                self.subscribed_spot_symbol_ids.add(self.default_symbol_id)
            else:
                print(f"Error: ctidTraderAccountId not set. Cannot subscribe to spots for {default_symbol_name}.")
                self._last_error = "ctidTraderAccountId not available for spot subscription after getting symbol details."
        elif self.default_symbol_id is not None:
            # This case should ideally not be hit if ProtoOASymbolByIdReq was successful for default_symbol_id
            print(f"Warning: Full details for default symbol ID {self.default_symbol_id} not found in response, cannot subscribe to its spots yet.")


    def _handle_account_auth_response(self, response: ProtoOAAccountAuthRes) -> None:
        print(f"Received ProtoOAAccountAuthRes: {response}")
        # The response contains the ctidTraderAccountId that was authenticated.
        # We should verify it matches the one we intended to authenticate.
        if response.ctidTraderAccountId == self.ctid_trader_account_id:
            print(f"Successfully authenticated account {self.ctid_trader_account_id}.")
            self.is_connected = True # Mark as connected for this specific account
            self._last_error = ""     # Clear any previous errors

            # After successful account auth, fetch initial trader details (balance, equity)
            self._send_get_trader_request(self.ctid_trader_account_id)

            # TODO: Subscribe to spots, etc., as needed by the application
            # self._send_subscribe_spots_request(symbol_id) # Example

            # After successful account auth, fetch symbol list to find default_symbol_id
            print("Account authenticated. Requesting symbols list...")
            self._send_get_symbols_list_request()

        else:
            print(f"AccountAuth failed. Expected ctidTraderAccountId {self.ctid_trader_account_id}, "
                  f"but response was for {response.ctidTraderAccountId if hasattr(response, 'ctidTraderAccountId') else 'unknown'}.")
            self._last_error = "Account authentication failed (ID mismatch or error)."
            self.is_connected = False
            # Consider stopping the client if account auth fails critically
            if self._client:
                self._client.stopService()

    def _handle_get_account_list_response(self, response: ProtoOAGetAccountListByAccessTokenRes) -> None:
        print("Account list response.")
        accounts = getattr(response, 'ctidTraderAccount', [])
        if not accounts:
            print("No accounts available for this access token.")
            self._last_error = "No trading accounts found for this access token."
            # Potentially disconnect or signal error more formally if no accounts mean connection cannot proceed.
            if self._client and self._is_client_connected:
                self._client.stopService() # Or some other error state
            return

        # TODO: If multiple accounts, allow user selection. For now, using the first.
        selected_account = accounts[0] # Assuming ctidTraderAccount is a list of ProtoOACtidTraderAccount
        if not selected_account.ctidTraderAccountId:
            print("Error: Account in list has no ctidTraderAccountId.")
            self._last_error = "Account found but missing ID."
            return

        self.ctid_trader_account_id = selected_account.ctidTraderAccountId
        print(f"Selected ctidTraderAccountId from list: {self.ctid_trader_account_id}")
        # Optionally save to settings if this discovery should update the default
        # self.settings.openapi.default_ctid_trader_account_id = self.ctid_trader_account_id

        # Now that we have a ctidTraderAccountId, authenticate this account
        self._send_account_auth_request(self.ctid_trader_account_id)

    def _handle_trader_response(self, response_wrapper: Any) -> None:
        # If this is called directly by a Deferred, response_wrapper might be ProtoMessage
        # If called after global _on_message_received, it's already extracted.
        if isinstance(response_wrapper, ProtoMessage):
            actual_message = Protobuf.extract(response_wrapper)
            print(f"_handle_trader_response: Extracted {type(actual_message)} from ProtoMessage wrapper.")
        else:
            actual_message = response_wrapper # Assume it's already the specific message type

        if not isinstance(actual_message, ProtoOATraderRes):
            print(f"_handle_trader_response: Expected ProtoOATraderRes, got {type(actual_message)}. Message: {actual_message}")
            return

        # Now actual_message is definitely ProtoOATraderRes
        trader_object = actual_message.trader # Access the nested ProtoOATrader object
        
        trader_details_updated = self._update_trader_details(
            "Trader details response.", trader_object
        )

        if trader_details_updated and hasattr(trader_object, 'ctidTraderAccountId'):
            current_ctid = getattr(trader_object, 'ctidTraderAccountId')
            print(f"Value of trader_object.ctidTraderAccountId before assignment: {current_ctid}, type: {type(current_ctid)}")
            self.account_id = str(current_ctid)
            print(f"self.account_id set to: {self.account_id}")
        elif trader_details_updated:
            print(f"Trader details updated, but ctidTraderAccountId missing from trader_object. trader_object: {trader_object}")
        else:
            print("_handle_trader_response: _update_trader_details did not return updated details or trader_object was None.")


    def _handle_trader_updated_event(self, event_wrapper: Any) -> None:
        if isinstance(event_wrapper, ProtoMessage):
            actual_event = Protobuf.extract(event_wrapper)
            print(f"_handle_trader_updated_event: Extracted {type(actual_event)} from ProtoMessage wrapper.")
        else:
            actual_event = event_wrapper

        if not isinstance(actual_event, ProtoOATraderUpdatedEvent):
            print(f"_handle_trader_updated_event: Expected ProtoOATraderUpdatedEvent, got {type(actual_event)}. Message: {actual_event}")
            return
            
        self._update_trader_details(
            "Trader updated event.", actual_event.trader # Access nested ProtoOATrader
        )
        # Note: TraderUpdatedEvent might not always update self.account_id if it's already set,
        # but it will refresh balance, equity, margin if present in actual_event.trader.

    def _update_trader_details(self, log_message: str, trader_proto: ProtoOATrader):
        """Helper to update trader balance and equity from a ProtoOATrader object."""
        print(log_message)
        if trader_proto:
            print(f"Full ProtoOATrader object received in _update_trader_details: {trader_proto}")

            # Safely get ctidTraderAccountId for logging, though it's not set here directly
            logged_ctid = getattr(trader_proto, 'ctidTraderAccountId', 'N/A')

            balance_val = getattr(trader_proto, 'balance', None)
            if balance_val is not None:
                self.balance = balance_val / 100.0
                print(f"  Updated balance for {logged_ctid}: {self.balance}")
            else:
                print(f"  Balance not found in ProtoOATrader for {logged_ctid}")

            equity_val = getattr(trader_proto, 'equity', None)
            if equity_val is not None:
                self.equity = equity_val / 100.0
                print(f"  Updated equity for {logged_ctid}: {self.equity}")
            else:
                # self.equity remains as its previous value (or None if first time)
                print(f"  Equity not found in ProtoOATrader for {logged_ctid}. self.equity remains: {self.equity}")
            
            currency_val = getattr(trader_proto, 'depositAssetId', None) # depositAssetId is often used for currency ID
            # TODO: Convert depositAssetId to currency string if mapping is available
            # For now, just store the ID if it exists, or keep self.currency as is.
            if currency_val is not None:
                 # self.currency = str(currency_val) # Or map to symbol
                 print(f"  depositAssetId (currency ID) for {logged_ctid}: {currency_val}")


            # Placeholder for margin - we need to see what fields are available from logs
            # Example:
            # used_margin_val = getattr(trader_proto, 'usedMargin', None) # Or 'totalMarginUsed' etc.
            # if used_margin_val is not None:
            #     self.used_margin = used_margin_val / 100.0
            #     print(f"  Updated used_margin for {logged_ctid}: {self.used_margin}")
            # else:
            #     print(f"  Used margin not found in ProtoOATrader for {logged_ctid}. self.used_margin remains: {self.used_margin}")

            return trader_proto
        else:
            print("_update_trader_details received empty trader_proto.")
        return None

    def _handle_spot_event(self, event: ProtoOASpotEvent) -> None:
        """Handles incoming spot events (price updates)."""
        # Log the raw event for debugging if needed, can be very noisy
        # print(f"Received ProtoOASpotEvent: {event}")

        # --- Trendbar Investigation (removed as it caused ValueError and trendbars were not populated) ---

        symbol_id = event.symbolId

        if self.default_symbol_id is not None and symbol_id == self.default_symbol_id:
            # The fields event.bid and event.timestamp are standard int64 fields in ProtoOASpotEvent.
            # For proto3, scalar fields don't use HasField in the same way as optional fields in proto2,
            # and will have default values (e.g., 0) if not explicitly set.
            # Given the logs show they are populated, we can proceed.
            # A price of 0 or timestamp of 0 would be unusual and might indicate an issue,
            # but the HasField check was the primary blocker for valid data.
            if event.timestamp == 0: # A timestamp of 0 is highly unlikely for a valid event
                print(f"Spot Event for default symbol {symbol_id} has timestamp 0. Skipping OHLC update.")
                return
            # A bid price of 0 could be technically possible in some rare market conditions,
            # but usually, for active forex pairs, it will be > 0.
            # For now, we'll proceed even with a bid of 0 if timestamp is valid,
            # as price scaling and strategy logic should handle price values.

            # Scale the price
            raw_bid_price = event.bid # Directly access, as HasField was problematic
            price_scale_factor = 100000.0 # Default
            if symbol_id in self.symbol_details_map:
                digits = self.symbol_details_map[symbol_id].digits
                price_scale_factor = float(10**digits)

            current_price = raw_bid_price / price_scale_factor

            # Update simple price history (for immediate price checks, GUI, etc.)
            self.price_history.append(current_price)
            if len(self.price_history) > self.history_size:
                self.price_history.pop(0)

            # OHLC Aggregation Logic
            event_dt = datetime.fromtimestamp(event.timestamp / 1000, tz=timezone.utc)

            for tf_str, tf_seconds in self.timeframes_seconds.items():
                current_tf_bar = self.current_bars[tf_str]

                if current_tf_bar['timestamp'] is None: # First tick for this timeframe or after a reset
                    current_tf_bar['timestamp'] = event_dt.replace(second= (event_dt.second // tf_seconds) * tf_seconds, microsecond=0)
                    current_tf_bar['open'] = current_price
                    current_tf_bar['high'] = current_price
                    current_tf_bar['low'] = current_price
                    current_tf_bar['close'] = current_price
                    current_tf_bar['volume'] = 1 # Tick count
                else:
                    # Check if current tick falls into a new bar interval
                    bar_end_time = current_tf_bar['timestamp'] + pd.Timedelta(seconds=tf_seconds)

                    if event_dt >= bar_end_time:
                        # Finalize the old bar
                        # The 'close' of the old bar is already set by the last tick that fell into it.
                        # (or it should be the last tick's price before this new one)
                        # For simplicity, current_tf_bar['close'] is the last tick's price of that bar.

                        # Add completed bar to history (if it has data)
                        if current_tf_bar['open'] is not None:
                            completed_bar_data = {
                                'timestamp': current_tf_bar['timestamp'], # Start time of the completed bar
                                'open': current_tf_bar['open'],
                                'high': current_tf_bar['high'],
                                'low': current_tf_bar['low'],
                                'close': current_tf_bar['close'], # Close of the *previous* bar
                                'volume': current_tf_bar['volume']
                            }
                            # Use pd.concat instead of append for DataFrames
                            self.ohlc_history[tf_str] = pd.concat([
                                self.ohlc_history[tf_str],
                                pd.DataFrame([completed_bar_data])
                            ], ignore_index=True)

                            # Keep history to max_ohlc_history_len
                            if len(self.ohlc_history[tf_str]) > self.max_ohlc_history_len:
                                self.ohlc_history[tf_str] = self.ohlc_history[tf_str].iloc[-self.max_ohlc_history_len:]

                            # Optional: Log completed bar
                            # print(f"Completed {tf_str} bar: O={completed_bar_data['open']:.5f} H={completed_bar_data['high']:.5f} L={completed_bar_data['low']:.5f} C={completed_bar_data['close']:.5f} V={completed_bar_data['volume']}")

                        # Start a new bar
                        current_tf_bar['timestamp'] = event_dt.replace(second=(event_dt.second // tf_seconds) * tf_seconds, microsecond=0)
                        current_tf_bar['open'] = current_price
                        current_tf_bar['high'] = current_price
                        current_tf_bar['low'] = current_price
                        current_tf_bar['close'] = current_price
                        current_tf_bar['volume'] = 1
                    else:
                        # Update current (still forming) bar
                        current_tf_bar['high'] = max(current_tf_bar['high'], current_price)
                        current_tf_bar['low'] = min(current_tf_bar['low'], current_price)
                        current_tf_bar['close'] = current_price
                        current_tf_bar['volume'] += 1

            # Optional: Log the latest tick after processing for OHLC
            # print(f"Spot Event for {symbol_id} (Default Symbol): Bid Price = {current_price:.5f}, History Size: {len(self.price_history)}")

        # else: # This was for non-default symbols, can be ignored for now
            # print(f"Spot Event for {symbol_id} (Default Symbol) received, but no bid price found in event.") # This log might be confusing now

        # Additionally, one might want to store the latest tick for all subscribed symbols,
        # This part is an extension and not strictly for self.price_history of the default symbol.
        # if symbol_id in self.subscribed_spot_symbol_ids:
        #    latest_bid = event.bid / price_scale_factor if event.HasField('bid') else None
        #    latest_ask = event.ask / price_scale_factor if event.HasField('ask') else None
        #    print(f"Tick for subscribed symbol {symbol_id}: Bid={latest_bid}, Ask={latest_ask}")
        #    # Store this latest_bid/ask in a suitable structure if needed for other parts of the app.

    def get_available_symbol_names(self) -> List[str]:
        """Returns a sorted list of symbol name strings available from the API."""
        if not self.symbols_map:
            return []
        return sorted(list(self.symbols_map.keys()))

    def _handle_execution_event(self, event: ProtoOAExecutionEvent) -> None:
        # TODO: handle executions
        pass

    def _handle_send_error(self, failure: Any) -> None:
        print(f"Send error: {failure.getErrorMessage()}")
        if hasattr(failure, 'printTraceback'):
            print("Traceback for send error:")
            failure.printTraceback(file=sys.stderr)
        else:
            print("Failure object does not have printTraceback method. Full failure object:")
            print(failure)
        self._last_error = failure.getErrorMessage()

    # Sending methods
    def _send_account_auth_request(self, ctid: int) -> None:
        if not self._ensure_valid_token():
            return # Token refresh failed or no token, error set by _ensure_valid_token

        print(f"Requesting AccountAuth for {ctid} with token: {self._access_token[:20]}...") # Log token used
        req = ProtoOAAccountAuthReq()
        req.ctidTraderAccountId = ctid
        req.accessToken = self._access_token or "" # Should be valid now

        print(f"Sending ProtoOAAccountAuthReq for ctid {ctid}: {req}")
        try:
            d = self._client.send(req)
            print(f"Deferred created for ProtoOAAccountAuthReq: {d}")

            def success_callback(response_msg):
                # This callback is mostly for confirming the Deferred fired successfully.
                # Normal processing will happen in _on_message_received if message is dispatched.
                print(f"AccountAuthReq success_callback triggered. Response type: {type(response_msg)}. Will be handled by _on_message_received.")
                # Note: We don't directly process response_msg here as _on_message_received should get it.

            def error_callback(failure_reason):
                print(f"AccountAuthReq error_callback triggered. Failure:")
                # Print a summary of the failure, and the full traceback if it's an exception
                if hasattr(failure_reason, 'getErrorMessage'):
                    print(f"  Error Message: {failure_reason.getErrorMessage()}")
                if hasattr(failure_reason, 'printTraceback'):
                    print(f"  Traceback for AccountAuthReq error:")
                    failure_reason.printTraceback(file=sys.stderr)
                else:
                    print(f"  Failure object (no printTraceback): {failure_reason}")
                self._handle_send_error(failure_reason) # Ensure our existing error handler is called

            d.addCallbacks(success_callback, errback=error_callback)
            print("Added callbacks to AccountAuthReq Deferred.")

        except Exception as e:
            print(f"Exception during _send_account_auth_request send command: {e}")
            self._last_error = f"Exception sending AccountAuth: {e}"
            # Potentially stop client if send itself fails critically
            if self._client and self._is_client_connected:
                self._client.stopService()
                self.is_connected = False # Ensure state reflects this

    def _send_get_account_list_request(self) -> None:
        if not self._ensure_valid_token():
            return

        print("Requesting account list.")
        req = ProtoOAGetAccountListByAccessTokenReq()
        if not self._access_token: # Should have been caught by _ensure_valid_token, but double check for safety
            self._last_error = "Critical: OAuth access token not available for GetAccountList request."
            print(self._last_error)
            if self._client:
                self._client.stopService()
            return
        req.accessToken = self._access_token
        print(f"Sending ProtoOAGetAccountListByAccessTokenReq: {req}")
        d = self._client.send(req)
        d.addCallbacks(self._handle_get_account_list_response, self._handle_send_error)

    def _send_get_trader_request(self, ctid: int) -> None:
        if not self._ensure_valid_token():
            return

        print(f"Requesting Trader details for {ctid}")
        req = ProtoOATraderReq()
        req.ctidTraderAccountId = ctid
        # Note: ProtoOATraderReq does not directly take an access token in its fields.
        # The authentication is expected to be session-based after AccountAuth.
        # If a token were needed here, the message definition would include it.
        print(f"Sending ProtoOATraderReq for ctid {ctid}: {req}")
        d = self._client.send(req)
        d.addCallbacks(self._handle_trader_response, self._handle_send_error)

    def _send_get_ctid_profile_request(self) -> None:
        """Sends a ProtoOAGetCtidProfileByTokenReq using the current OAuth access token."""
        if not self._ensure_valid_token(): # Ensure token is valid before using it
            return

        if not self._access_token:
            self._last_error = "Critical: OAuth access token not available for GetCtidProfile request."
            print(self._last_error)
            if self._client and self._is_client_connected:
                self._client.stopService()
            return

        print("Sending ProtoOAGetCtidProfileByTokenReq...")
        req = ProtoOAGetCtidProfileByTokenReq()
        req.accessToken = self._access_token

        print(f"Sending ProtoOAGetCtidProfileByTokenReq: {req}")
        try:
            d = self._client.send(req)
            print(f"Deferred created for ProtoOAGetCtidProfileByTokenReq: {d}")

            # Adding specific callbacks for this request to see its fate
            def profile_req_success_callback(response_msg):
                print(f"GetCtidProfileByTokenReq success_callback triggered. Response type: {type(response_msg)}. Will be handled by _on_message_received.")

            def profile_req_error_callback(failure_reason):
                print(f"GetCtidProfileByTokenReq error_callback triggered. Failure:")
                if hasattr(failure_reason, 'getErrorMessage'):
                    print(f"  Error Message: {failure_reason.getErrorMessage()}")
                if hasattr(failure_reason, 'printTraceback'): # May be verbose
                    print(f"  Traceback for GetCtidProfileByTokenReq error:")
                    failure_reason.printTraceback(file=sys.stderr)
                else:
                    print(f"  Failure object (no printTraceback): {failure_reason}")
                self._handle_send_error(failure_reason)

            d.addCallbacks(profile_req_success_callback, errback=profile_req_error_callback)
            print("Added callbacks to GetCtidProfileByTokenReq Deferred.")

        except Exception as e:
            print(f"Exception during _send_get_ctid_profile_request send command: {e}")
            self._last_error = f"Exception sending GetCtidProfile: {e}"
            if self._client and self._is_client_connected:
                self._client.stopService()
                self.is_connected = False

    def _send_subscribe_spots_request(self, ctid_trader_account_id: int, symbol_ids: List[int]) -> None:
        """Sends a ProtoOASubscribeSpotsReq to subscribe to spot prices for given symbol IDs."""
        if not self._ensure_valid_token():
            return
        if not self._client or not self._is_client_connected:
            self._last_error = "Cannot subscribe to spots: Client not connected."
            print(self._last_error)
            return
        if not ctid_trader_account_id:
            self._last_error = "Cannot subscribe to spots: ctidTraderAccountId is not set."
            print(self._last_error)
            return
        if not symbol_ids:
            self._last_error = "Cannot subscribe to spots: No symbol_ids provided."
            print(self._last_error)
            return

        print(f"Requesting spot subscription for account {ctid_trader_account_id} and symbols {symbol_ids}")
        req = ProtoOASubscribeSpotsReq()
        req.ctidTraderAccountId = ctid_trader_account_id
        req.symbolId.extend(symbol_ids) # symbolId is a repeated field

        # clientMsgId can be set if needed, but for subscriptions, the server pushes updates
        # req.clientMsgId = self._next_message_id()

        print(f"Sending ProtoOASubscribeSpotsReq: {req}")
        try:
            d = self._client.send(req)
            # Add callbacks: one for the direct response to the subscription request,
            # and one for handling errors during sending.
            # Spot events themselves will be handled by _on_message_received -> _handle_spot_event.
            d.addCallbacks(
                lambda response: self._handle_subscribe_spots_response(response, symbol_ids),
                self._handle_send_error
            )
            print("Added callbacks to ProtoOASubscribeSpotsReq Deferred.")
        except Exception as e:
            print(f"Exception during _send_subscribe_spots_request send command: {e}")
            self._last_error = f"Exception sending spot subscription: {e}"


    # Public API
    def connect(self) -> bool:
        """
        Establishes a connection to the trading service.
        Handles OAuth2 flow (token loading, refresh, or full browser authentication)
        and then starts the underlying OpenAPI client service.

        Returns:
            True if connection setup (including successful client service start) is successful,
            False otherwise.
        """
        if not USE_OPENAPI_LIB:
            print("Mock mode: OpenAPI library unavailable.")
            self._last_error = "OpenAPI library not available (mock mode)."
            return False

        # 1. Check if loaded token is valid and not expired
        self._last_error = "Checking saved tokens..." # For GUI
        if self._access_token and not self._is_token_expired():
            print("Using previously saved, valid access token.")
            self._last_error = "Attempting to connect with saved token..." # For GUI
            if self._start_openapi_client_service():
                return True # Proceed with this token
            else:
                # Problem starting client service even with a seemingly valid token
                # self._last_error is set by _start_openapi_client_service
                print(f"Failed to start client service with saved token: {self._last_error}")
                # Fall through to try refresh or full OAuth
                self._access_token = None # Invalidate to ensure we don't retry this path immediately

        # 2. If token is expired or (now) no valid token, try to refresh if possible
        if self._refresh_token: # Check if refresh is even possible
            if self._access_token and self._is_token_expired(): # If previous step invalidated or was originally expired
                print("Saved access token is (or became) invalid/expired, attempting refresh...")
            elif not self._access_token: # No access token from file, but refresh token exists
                 print("No saved access token, but refresh token found. Attempting refresh...")

            self._last_error = "Attempting to refresh token..." # For GUI
            if self.refresh_access_token(): # This also saves the new token
                print("Access token refreshed successfully using saved refresh token.")
                self._last_error = "Token refreshed. Attempting to connect..." # For GUI
                if self._start_openapi_client_service():
                    return True # Proceed with refreshed token
                else:
                    # self._last_error set by _start_openapi_client_service
                    print(f"Failed to start client service after token refresh: {self._last_error}")
                    return False # Explicitly fail here if client service fails after successful refresh
            else:
                print("Failed to refresh token. Proceeding to full OAuth flow.")
                # self._last_error set by refresh_access_token(), fall through to full OAuth
        else:
            print("No refresh token available. Proceeding to full OAuth if needed.")


        # 3. If no valid/refreshed token, proceed to full OAuth browser flow
        print("No valid saved token or refresh failed/unavailable. Initiating full OAuth2 flow...")
        self._last_error = "OAuth2: Redirecting to browser for authentication." # More specific initial status

        auth_url = self.settings.openapi.spotware_auth_url
        # token_url = self.settings.openapi.spotware_token_url # Not used in this part of connect()
        client_id = self.settings.openapi.client_id
        redirect_uri = self.settings.openapi.redirect_uri
        # Define scopes - this might need adjustment based on Spotware's requirements
        scopes = "accounts" # Changed from "trading accounts" to just "accounts" based on OpenApiPy example hint

        # Construct the authorization URL using the new Spotware URL
        # Construct the authorization URL using the standard Spotware OAuth endpoint.
        params = {
            "response_type": "code", # Required for Authorization Code flow
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scopes
            # product="web" is removed as it's not part of standard OAuth params here
            # "state": "YOUR_UNIQUE_STATE_HERE" # Optional: for CSRF protection
        }
        auth_url_with_params = f"{auth_url}?{urllib.parse.urlencode(params)}"

        # At this point, the application will wait. The user needs to authenticate
        # in the browser, and then manually provide the authorization code.
        # The actual connection to Spotware (self._client.startService()) will be
        # deferred until after the auth code is obtained and exchanged for a token.
        # For this step, returning False means the immediate connection via TCP client isn't made yet.
        # The GUI should reflect the status "Awaiting browser authentication".
        # This method will now block until code is received or timeout.
        # For GUI responsiveness, Trader.connect might need to run in a thread
        # or use async mechanisms if this blocking is too long.
        # For now, assume GUI can handle a short blocking period or this runs in a bg thread.

        # Start local HTTP server
        if not self._start_local_http_server():
            self._last_error = "OAuth2 Error: Could not start local HTTP server for callback."
            print(self._last_error)
            return False # Indicate connection failed

        print(f"Redirecting to browser for authentication: {auth_url_with_params}")
        webbrowser.open(auth_url_with_params)
        self._last_error = "OAuth2: Waiting for authorization code via local callback..." # Update status

        # Wait for the auth code from the HTTP server (with a timeout)
        try:
            auth_code = self._auth_code_queue.get(timeout=120) # 2 minutes timeout
            print("Authorization code received from local server.")
        except queue.Empty:
            print("OAuth2 Error: Timeout waiting for authorization code from callback.")
            self._last_error = "OAuth2 Error: Timeout waiting for callback."
            self._stop_local_http_server()
            return False

        self._stop_local_http_server()

        if auth_code:
            return self.exchange_code_for_token(auth_code)
        else: # Should not happen if queue contained None or empty string but good to check
            self._last_error = "OAuth2 Error: Invalid authorization code received."
            print(self._last_error)
            return False


    def _start_local_http_server(self) -> bool:
        """
        Starts a local HTTP server on a separate thread to listen for the OAuth callback.
        The server address is determined by self.settings.openapi.redirect_uri.

        Returns:
            True if the server started successfully, False otherwise.
        """
        try:
            # Ensure any previous server is stopped
            if self._http_server_thread and self._http_server_thread.is_alive():
                self._stop_local_http_server()

            # Use localhost and port from redirect_uri
            parsed_uri = urllib.parse.urlparse(self.settings.openapi.redirect_uri)
            host = parsed_uri.hostname
            port = parsed_uri.port

            if not host or not port:
                print(f"Invalid redirect_uri for local server: {self.settings.openapi.redirect_uri}")
                return False

            # Pass the queue to the handler
            def handler_factory(*args, **kwargs):
                return OAuthCallbackHandler(*args, auth_code_queue=self._auth_code_queue, **kwargs)

            self._http_server = HTTPServer((host, port), handler_factory)
            self._http_server_thread = threading.Thread(target=self._http_server.serve_forever, daemon=True)
            self._http_server_thread.start()
            print(f"Local HTTP server started on {host}:{port} for OAuth callback.")
            return True
        except Exception as e:
            print(f"Failed to start local HTTP server: {e}")
            self._last_error = f"Failed to start local HTTP server: {e}"
            return False

    def _stop_local_http_server(self):
        if self._http_server:
            print("Shutting down local HTTP server...")
            self._http_server.shutdown() # Signal server to stop serve_forever loop
            self._http_server.server_close() # Close the server socket
            self._http_server = None
        if self._http_server_thread and self._http_server_thread.is_alive():
            self._http_server_thread.join(timeout=5) # Wait for thread to finish
            if self._http_server_thread.is_alive():
                print("Warning: HTTP server thread did not terminate cleanly.")
        self._http_server_thread = None
        print("Local HTTP server stopped.")


    def exchange_code_for_token(self, auth_code: str) -> bool:
        """
        Exchanges an OAuth authorization code for an access token and refresh token.
        Saves tokens to file on success and starts the OpenAPI client service.

        Args:
            auth_code: The authorization code obtained from the OAuth provider.

        Returns:
            True if token exchange and client service start were successful, False otherwise.
        """
        print(f"Exchanging authorization code for token: {auth_code[:20]}...") # Log part of the code
        self._last_error = ""
        try:
            token_url = self.settings.openapi.spotware_token_url
            payload = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": self.settings.openapi.redirect_uri,
                "client_id": self.settings.openapi.client_id,
                "client_secret": self.settings.openapi.client_secret,
            }
            response = requests.post(token_url, data=payload)
            response.raise_for_status()  # Raises an HTTPError for bad responses (4XX or 5XX)

            token_data = response.json()

            if "access_token" not in token_data:
                self._last_error = "OAuth2 Error: access_token not in response from token endpoint."
                print(f"{self._last_error} Response: {token_data}")
                return False

            self._access_token = token_data["access_token"]
            self._refresh_token = token_data.get("refresh_token") # refresh_token might not always be present
            expires_in = token_data.get("expires_in")
            if expires_in:
                self._token_expires_at = time.time() + int(expires_in)
            else:
                self._token_expires_at = None # Or a very long time if not specified

            print(f"Access token obtained: {self._access_token[:20]}...")
            if self._refresh_token:
                print(f"Refresh token obtained: {self._refresh_token[:20]}...")
            print(f"Token expires in: {expires_in} seconds (at {self._token_expires_at})")

            # Now that we have the access token, we can start the actual OpenAPI client service
            self._save_tokens_to_file() # Save tokens after successful exchange
            if self._start_openapi_client_service():
                # Connection to TCP endpoint will now proceed, leading to ProtoOAApplicationAuthReq etc.
                # The _check_connection in GUI will handle the rest.
                return True
            else:
                # _start_openapi_client_service would have set _last_error
                return False

        except requests.exceptions.HTTPError as http_err:
            error_content = http_err.response.text
            self._last_error = f"OAuth2 HTTP Error: {http_err}. Response: {error_content}"
            print(self._last_error)
            return False
        except requests.exceptions.RequestException as req_err:
            self._last_error = f"OAuth2 Request Error: {req_err}"
            print(self._last_error)
            return False
        except Exception as e:
            self._last_error = f"OAuth2 Unexpected Error during token exchange: {e}"
            print(self._last_error)
            return False

    def _start_openapi_client_service(self):
        """
        Starts the underlying OpenAPI client service (TCP connection, reactor).
        This is called after successful OAuth token acquisition/validation.

        Returns:
            True if the client service started successfully, False otherwise.
        """
        if self.is_connected or (self._client and getattr(self._client, 'isConnected', False)):
            print("OpenAPI client service already running or connected.")
            return True

        print("Starting OpenAPI client service.")
        try:
            self._client.startService()
            if _reactor_installed and not reactor.running:
                self._reactor_thread = threading.Thread(target=lambda: reactor.run(installSignalHandlers=0), daemon=True)
                self._reactor_thread.start()
            return True
        except Exception as e:
            print(f"Error starting OpenAPI client service: {e}")
            self._last_error = f"OpenAPI client error: {e}"
            return False

    def refresh_access_token(self) -> bool:
        """
        Refreshes the OAuth access token using the stored refresh token.
        Saves the new tokens to file on success.

        Returns:
            True if the access token was refreshed successfully, False otherwise.
        """
        if not self._refresh_token:
            self._last_error = "OAuth2 Error: No refresh token available to refresh access token."
            print(self._last_error)
            return False

        print("Attempting to refresh access token...")
        self._last_error = ""
        try:
            token_url = self.settings.openapi.spotware_token_url
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
                "client_id": self.settings.openapi.client_id,
                "client_secret": self.settings.openapi.client_secret, # Typically required for refresh
            }
            response = requests.post(token_url, data=payload)
            response.raise_for_status()

            token_data = response.json()

            if "access_token" not in token_data:
                self._last_error = "OAuth2 Error: access_token not in response from refresh token endpoint."
                print(f"{self._last_error} Response: {token_data}")
                # Potentially invalidate old tokens if refresh fails this way
                self.is_connected = False
                return False

            self._access_token = token_data["access_token"]
            # A new refresh token might be issued, or the old one might continue to be valid.
            # Standard practice: if a new one is issued, use it. Otherwise, keep the old one.
            if "refresh_token" in token_data:
                self._refresh_token = token_data["refresh_token"]
                print(f"New refresh token obtained: {self._refresh_token[:20]}...")

            expires_in = token_data.get("expires_in")
            if expires_in:
                self._token_expires_at = time.time() + int(expires_in)
            else:
                # If expires_in is not provided on refresh, it might mean the expiry doesn't change
                # or it's a non-expiring token (less common). For safety, clear old expiry.
                self._token_expires_at = None

            print(f"Access token refreshed successfully: {self._access_token[:20]}...")
            print(f"New expiry: {self._token_expires_at}")
            self._save_tokens_to_file() # Save tokens after successful refresh
            return True

        except requests.exceptions.HTTPError as http_err:
            error_content = http_err.response.text
            self._last_error = f"OAuth2 HTTP Error during token refresh: {http_err}. Response: {error_content}"
            print(self._last_error)
            self.is_connected = False # Assume connection is lost if refresh fails
            return False
        except requests.exceptions.RequestException as req_err:
            self._last_error = f"OAuth2 Request Error during token refresh: {req_err}"
            print(self._last_error)
            self.is_connected = False
            return False
        except Exception as e:
            self._last_error = f"OAuth2 Unexpected Error during token refresh: {e}"
            print(self._last_error)
            self.is_connected = False
            return False

    def _is_token_expired(self, buffer_seconds: int = 60) -> bool:
        """
        Checks if the current OAuth access token is expired or nearing expiry.

        Args:
            buffer_seconds: A buffer time in seconds. If the token expires within
                            this buffer, it's considered nearing expiry.

        Returns:
            True if the token is non-existent, expired, or nearing expiry, False otherwise.
        """
        if not self._access_token:
            return True # No token means it's effectively expired for use
        if self._token_expires_at is None:
            return False # Token that doesn't expire (or expiry unknown)
        return time.time() > (self._token_expires_at - buffer_seconds)

    def _ensure_valid_token(self) -> bool:
        """
        Ensures the OAuth access token is valid, attempting a refresh if it's expired or nearing expiry.
        This is a proactive check typically called before making an API request that requires auth.

        Returns:
            True if a valid token is present (either initially or after successful refresh),
            False if no valid token is available and refresh failed or was not possible.
        """
        if self._is_token_expired():
            print("Access token expired or nearing expiry. Attempting refresh.")
            if not self.refresh_access_token():
                print("Failed to refresh access token.")
                # self._last_error is set by refresh_access_token()
                if self._client and self._is_client_connected: # Check if client exists and was connected
                    self._client.stopService() # Stop service if token cannot be refreshed
                self.is_connected = False
                return False
        return True


    def disconnect(self) -> None:
        if self._client:
            self._client.stopService()
        if _reactor_installed and reactor.running:
            reactor.callFromThread(reactor.stop)
        self.is_connected = False
        self._is_client_connected = False

    def get_connection_status(self) -> Tuple[bool, str]:
        return self.is_connected, self._last_error

    def get_account_summary(self) -> Dict[str, Any]:
        if not USE_OPENAPI_LIB:
            return {"account_id": "MOCK", "balance": 0.0, "equity": 0.0, "margin": 0.0}
        if not self.is_connected:
            # Return current values even if not fully "connected" but some data might be partially loaded
            return {
                "account_id": self.account_id if self.account_id else "connecting...",
                "balance": self.balance,
                "equity": self.equity,
                "margin": self.used_margin
            }
        return {
            "account_id": self.account_id,
            "balance": self.balance,
            "equity": self.equity,
            "margin": self.used_margin # This will be None initially, or updated from ProtoOATrader
        }

    def get_market_price(self, symbol: str) -> Optional[float]:
        """
        Returns the latest market price (bid) for the default subscribed symbol.
        The 'symbol' argument is currently ignored as price_history is only maintained
        for the default_symbol_id. Future enhancements could allow fetching prices
        for other subscribed symbols if latest ticks are stored separately.
        """
        if not USE_OPENAPI_LIB:
            # Mock mode: return a random price
            print(f"Mock mode: Returning random price for {symbol}")
            return round(random.uniform(1.10, 1.20), 5)

        if self.default_symbol_id is None:
            print(f"Warning: Default symbol ID not set. Cannot get market price for {symbol}.")
            return None

        # Currently, price_history is only for the default_symbol_id
        # We also check if the requested symbol matches the default symbol name from settings for clarity,
        # though technically self.price_history is always for default_symbol_id.
        if symbol != self.settings.general.default_symbol:
            print(f"Warning: get_market_price currently only supports the default symbol '{self.settings.general.default_symbol}'. Requested: '{symbol}'. Returning latest from default history if available.")
            # Depending on strictness, one might return None here.
            # For now, proceed to return default symbol's last price.

        if not self.price_history:
            # print(f"No price history available for default symbol ({self.settings.general.default_symbol}). Cannot get market price.")
            return None # No data yet

        return self.price_history[-1]

    def get_price_history(self) -> List[float]:
        return list(self.price_history)
