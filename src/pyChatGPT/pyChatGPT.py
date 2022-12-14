from playwright._impl import _api_types as PlaywrightError
from playwright.sync_api import sync_playwright, Route
from cf_clearance import sync_stealth

from pyvirtualdisplay import Display
import markdownify
import platform
import json
import os
import re


class ChatGPT:
    '''
    An unofficial Python wrapper for OpenAI's ChatGPT API
    '''

    def __init__(
        self,
        session_token: str = None,
        email: str = None,
        password: str = None,
        auth_type: str = None,
        proxy: str = None,
        verbose: bool = False,
    ) -> None:
        '''
        Initialize the ChatGPT class\n
        Either provide a session token or email and password\n
        Parameters:
        - session_token: (optional) Your session token in cookies named as `__Secure-next-auth.session-token` from https://chat.openai.com/chat
        - email: (optional) Your email
        - password: (optional) Your password
        - auth_type: The type of authentication to use. Can only be `google` at the moment
        - proxy: (optional) The proxy to use, in URL format (i.e. `https://ip:port`)
        - verbose: (optional) Whether to print debug messages
        '''
        self.__verbose = verbose

        self.__proxy = proxy
        if self.__proxy and not re.findall(
            r'(https?|socks(4|5)?):\/\/.+:\d{1,5}', self.__proxy
        ):
            raise ValueError('Invalid proxy format')

        self.__email = email
        self.__password = password
        self.__auth_type = auth_type
        if self.__auth_type not in [None, 'google', 'windowslive']:
            raise ValueError('Invalid authentication type')
        self.__session_token = session_token
        if not self.__session_token:
            if not self.__email or not self.__password or not self.__auth_type:
                raise ValueError(
                    'Please provide either a session token or login credentials'
                )

        self.__is_headless = (
            platform.system() == 'Linux' and 'DISPLAY' not in os.environ
        )
        self.__verbose_print('[0] Platform:', platform.system())
        self.__verbose_print('[0] Display:', 'DISPLAY' in os.environ)
        self.__verbose_print('[0] Headless:', self.__is_headless)
        self.__init_browser()

    def __verbose_print(self, *args, **kwargs) -> None:
        '''
        Print if verbose is enabled
        '''
        if self.__verbose:
            print(*args, **kwargs)

    def close(self) -> None:
        '''
        Close the browser and stop the virtual display (if any)
        '''
        if hasattr(self, 'driver'):
            self.driver.quit()
        if hasattr(self, 'display'):
            self.display.stop()

    def __init_browser(self) -> None:
        '''
        Initialize the browser
        '''
        # Detect if running on a headless server
        if self.__is_headless:
            try:
                self.display = Display()
            except FileNotFoundError as e:
                if 'No such file or directory: \'Xvfb\'' in str(e):
                    raise ValueError(
                        'Headless machine detected. Please install Xvfb to start a virtual display: sudo apt install xvfb'
                    )
                raise e
            self.__verbose_print('[init] Starting virtual display')
            self.display.start()

        # Start the browser
        self.__verbose_print('[init] Starting browser')
        self.playwright = sync_playwright().start()
        if self.__proxy:
            self.__verbose_print('[init] Using proxy', self.__proxy)
            self.__browser = self.playwright.chromium.launch(
                headless=False, proxy={'server': self.__proxy}
            )
        else:
            self.__browser = self.playwright.chromium.launch(headless=False)

        # Create a new page
        self.__context = self.__browser.new_context()
        self.__page = self.__context.new_page()
        sync_stealth(self.__page, pure=False)

        # Restore session token
        if not self.__auth_type:
            self.__verbose_print('[init] Restoring session token')
            self.__page.context.add_cookies(
                [
                    {
                        'domain': 'chat.openai.com',
                        'path': '/',
                        'name': '__Secure-next-auth.session-token',
                        'value': self.__session_token,
                        'httpOnly': True,
                        'secure': True,
                    }
                ]
            )

        # Ensure that the Cloudflare cookies is still valid
        self.__verbose_print('[init] Ensuring Cloudflare cookies')
        self.__ensure_cf()

        # Open the chat page
        self.__verbose_print('[init] Opening chat page')
        self.__page.goto('https://chat.openai.com/chat')

        # Dismiss the ChatGPT intro
        self.__verbose_print('[init] Check if there is intro')
        try:
            self.__page.locator('id=headlessui-portal-root').wait_for(
                timeout=3000, state='hidden'
            )
            self.__verbose_print('[init] Dismissing intro')
            self.__page.evaluate(
                """() => {
            var element = document.getElementById('headlessui-portal-root');
            if (element)
                element.parentNode.removeChild(element);
            }"""
            )
        except PlaywrightError.TimeoutError:
            self.__verbose_print('[init] Did not found one')
            pass

    def __login(self) -> None:
        '''
        Login to ChatGPT
        '''
        # Get the login page
        self.__verbose_print('[login] Opening new tab')
        self.__login_page = self.__context.new_page()
        sync_stealth(self.__login_page, pure=False)

        self.__verbose_print('[login] Opening login page')
        self.__login_page.goto('https://chat.openai.com/auth/login')
        while True:
            try:
                self.__verbose_print('[login] Checking if ChatGPT is at capacity')
                self.__login_page.locator(
                    "div:has-text('ChatGPT is at capacity right now')"
                ).wait_for(timeout=3000)
                self.__verbose_print('[login] ChatGPT is at capacity, retrying')
                self.__login_page.goto('https://chat.openai.com/auth/login')
            except PlaywrightError.TimeoutError:
                self.__verbose_print('[login] ChatGPT is not at capacity')
                break

        # Click Log in button
        self.__verbose_print('[login] Clicking Log in button')
        self.__login_page.locator('button:has-text("Log in")').click()

        # click button with data-provider="google"
        self.__verbose_print('[login] Clicking Google button')
        self.__login_page.locator('h1:has-text("Welcome back")').wait_for(timeout=5000)
        self.__login_page.locator(
            f'//button[@data-provider="{self.__auth_type}"]'
        ).click()

        if self.__auth_type == 'google':
            # Enter email
            try:
                self.__verbose_print('[login] Checking if Google remembers email')
                self.__login_page.locator(
                    f'//div[@data-identifier="{self.__email}"]'
                ).wait_for(timeout=3000)
                self.__verbose_print('[login] Google remembers email')
                self.__login_page.locator(
                    f'//div[@data-identifier="{self.__email}"]'
                ).click()
            except PlaywrightError.TimeoutError:
                self.__verbose_print('[login] Google does not remember email')
                self.__verbose_print('[login] Entering email')
                self.__login_page.locator('//input[@type="email"]').fill(self.__email)
                self.__verbose_print('[login] Clicking Next')
                self.__login_page.locator('//*[@id="identifierNext"]').click()

                # Enter password
                self.__verbose_print('[login] Entering password')
                self.__login_page.locator('//input[@type="password"]').fill(
                    self.__password
                )
                self.__verbose_print('[login] Clicking Next')
                self.__login_page.locator('//*[@id="passwordNext"]').click()

            # wait verification code
            try:
                self.__verbose_print('[login] Check if verification code is required')
                self.__login_page.locator('samp').wait_for(timeout=5000)
                self.__verbose_print('[login] code is required')
                prev_code = self.__login_page.locator('samp').inner_text()
                print('Verification code:', prev_code)
                while True:
                    try:
                        code = self.__login_page.locator('samp').inner_text()
                    except PlaywrightError.TimeoutError:
                        break
                    if code != prev_code:
                        print('Verification code:', code)
                        prev_code = code
                    self.__login_page.wait_for_timeout(1000)
            except PlaywrightError.TimeoutError:
                self.__verbose_print('[login] code is not required')
                pass

        # Check if logged in correctly
        try:
            self.__verbose_print('[login] Checking if login was successful')
            self.__login_page.locator('h1:has-text("ChatGPT")').wait_for(timeout=5000)
        except PlaywrightError.TimeoutError:
            self.driver.save_screenshot('login_failed.png')
            raise ValueError('Login failed')

        # Close the tab
        self.__verbose_print('[login] Closing tab')
        self.__login_page.close()

    def __ensure_cf(self, retry: int = 0) -> None:
        '''
        Ensure that the Cloudflare cookies is still valid\n
        Parameters:
        - retry: The number of times this function has been called recursively
        '''
        # Open a new tab
        self.__verbose_print('[cf] Opening new tab')
        self.__cf_page = self.__context.new_page()
        sync_stealth(self.__cf_page, pure=False)

        # Get the Cloudflare challenge
        self.__verbose_print('[cf] Getting authorization')
        self.__cf_page.goto('https://chat.openai.com/api/auth/session')
        try:
            self.__cf_page.locator('id=challenge-form').wait_for(
                timeout=15000, state='detached'
            )
        except PlaywrightError.TimeoutError:
            if retry <= 4:
                self.__verbose_print(
                    f'[cf] Cloudflare challenge failed, retrying {retry + 1}'
                )
                self.__verbose_print('[cf] Closing tab')
                self.__cf_page.close()
                return self.__ensure_cf(retry + 1)
            else:
                resp_text = self.__cf_page.content()
                raise ValueError(f'Cloudflare challenge failed: {resp_text}')

        # Validate the authorization
        self.__verbose_print('[cf] Validating authorization')
        resp = self.__cf_page.content()
        if resp[0] != '{':  # its probably not a json
            self.__verbose_print('[cf] resp is not json')
            resp = self.__cf_page.locator('pre').inner_text()
        data = json.loads(resp)
        if data and 'error' in data:
            self.__verbose_print(f'[cf] {data["error"]}')
            if data['error'] == 'RefreshAccessTokenError':
                if not self.__auth_type:
                    raise ValueError('Session token expired')
                self.__login()
            else:
                raise ValueError(f'Authorization error: {data["error"]}')
        elif not data:
            self.__verbose_print('[cf] Authorization is empty')
            if not self.__auth_type:
                raise ValueError('Invalid session token')
            self.__login()
        self.__verbose_print('[cf] Authorization is valid')

        # Close the tab
        self.__verbose_print('[cf] Closing tab')
        self.__cf_page.close()

    def __conversation_handler(self, route: Route, conversation_id, parent_id):
        request = route.request
        payload = request.post_data_json
        if conversation_id:
            payload['conversation_id'] = conversation_id
        if parent_id:
            payload['parent_message_id'] = parent_id
        dump = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
        route.continue_(post_data=dump)

    def __moderations_handler(self, route: Route):
        request = route.request
        payload = request.post_data_json
        payload['input'] = 'Hi'
        dump = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
        route.continue_(post_data=dump)

    def send_message(
        self, message: str, conversation_id: str = None, parent_id: str = None
    ) -> dict:
        '''
        Send a message to the chatbot\n
        Parameters:
        - message: The message you want to send
        - conversation_id: The conversation ID
        - parent_id: The parent ID\n
        Returns a `dict` with the following keys:
        - message: The message the chatbot sent
        - conversation_id: The conversation ID. Always returns empty string
        - parent_id: The parent ID. Always returns empty string
        '''
        # Ensure that the Cloudflare cookies is still valid
        self.__verbose_print('[send_msg] Ensuring Cloudflare cookies')
        self.__ensure_cf()

        # Intercept the conversation
        self.__page.route(
            'https://chat.openai.com/backend-api/conversation',
            lambda route: self.__conversation_handler(
                route, conversation_id, parent_id
            ),
        )
        self.__page.route(
            'https://chat.openai.com/backend-api/moderations',
            lambda route: self.__moderations_handler(route),
        )

        # Send the message
        self.__verbose_print('[send_msg] Sending message')
        textarea = self.__page.locator('textarea')
        textarea.fill(message)
        textarea.press('Enter')

        # Wait for the response to be ready
        self.__verbose_print('[send_msg] Waiting for completion')
        self.__page.locator('.result-streaming').wait_for(timeout=90000, state='hidden')

        # Get the response element
        self.__verbose_print('[send_msg] Finding response element')
        response = self.__page.locator(
            'xpath=//div[starts-with(@class, "request-:")] >> nth=-1'
        )

        # Check if the response is an error
        self.__verbose_print('[send_msg] Checking if response is an error')
        if 'text-red' in response.get_attribute('class'):
            self.__verbose_print('[send_msg] Response is an error')
            raise ValueError(response.text)
        self.__verbose_print('[send_msg] Response is not an error')

        # Return the response
        return {
            'message': markdownify.markdownify(response.inner_html()),
            'conversation_id': '',
            'parent_id': '',
        }

    def reset_conversation(self) -> None:
        '''
        Reset the conversation
        '''
        self.__verbose_print('Resetting conversation')
        self.__page.locator("a:has-text('New Thread')").click()
