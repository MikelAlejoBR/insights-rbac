#
# Copyright 2024 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Test the principal model."""
import requests
import uuid

from django.conf import settings

from management.principal.it_service import ITService, UnexpectedStatusCodeFromITError
from rest_framework import serializers, status
from tests.identity_request import IdentityRequest
from unittest import mock

from api.models import User

# IT path to fetch the service accounts.
IT_PATH_GET_SERVICE_ACCOUNTS = "/service_accounts/v1"


class ITServiceTests(IdentityRequest):
    """Test the IT service class"""

    def setUp(self):
        # Set up some settings so that the class builds IT's URL.
        settings.IT_SERVICE_HOST = "localhost"
        settings.IT_SERVICE_BASE_PATH = "/"
        settings.IT_SERVICE_PORT = "999"
        settings.IT_SERVICE_PROTOCOL_SCHEME = "http"
        settings.IT_SERVICE_TIMEOUT_SECONDS = 10

        self.it_service = ITService()

    def _create_mock_it_service_accounts(self, number: int) -> list[dict[str, str]]:
        """Create mock service accounts as returned by IT."""
        service_accounts: list[dict] = []
        for i in range(number):
            client_id = str(uuid.uuid4())

            service_accounts.append(
                {
                    "clientId": client_id,
                    "name": f"name-{client_id}",
                    "description": f"description-{client_id}",
                    "createdBy": f"createdBy-{client_id}",
                    "createdAt": f"createdAt-{client_id}",
                }
            )

        return service_accounts

    def _assert_IT_to_RBAC_model_transformations(
        self, it_service_accounts: list[dict[str, str]], rbac_service_accounts: list[dict[str, str]]
    ) -> None:
        """Assert that the service accounts coming from IT were correctly transformed into our model"""
        # Rearrange RBAC's service accounts by client ID for an easier search later on.
        rbac_service_accounts_by_cid: dict[str, dict[str, str]] = {}
        for rbac_sa in rbac_service_accounts:
            rbac_sa_cid = rbac_sa.get("clientID")
            if not rbac_sa_cid:
                self.fail(f'the transformed service account does not have the "clientID" property: {rbac_sa}')

            rbac_service_accounts_by_cid[rbac_sa_cid] = rbac_sa

        # Make all the assertions for the contents.
        for it_sa in it_service_accounts:
            client_id = it_sa.get("clientId")
            if not client_id:
                self.fail(f'the IT service account dictionary does not have the "clientId" property: {it_sa}')

            rbac_sa = rbac_service_accounts_by_cid.get(client_id)
            if not rbac_sa:
                self.fail(
                    f"the transformed RBAC service accounts do not contain a service account with client ID"
                    f' "{client_id}". RBAC service accounts: {rbac_service_accounts_by_cid}'
                )

            # Assert that the client IDs are the same.
            rbac_sa_client_id = rbac_sa.get("clientID")
            if not rbac_sa_client_id:
                self.fail(f'the transformed RBAC service account does not contain the "clientID" property: {rbac_sa}')

            self.assertEqual(rbac_sa_client_id, client_id, "the client IDs for the RBAC and IT models do not match")

            # Assert that the names are the same.
            rbac_sa_name = rbac_sa.get("name")
            if not rbac_sa_name:
                self.fail(f'the transformed RBAC service account does not contain the "name" property: {rbac_sa}')

            it_sa_name = it_sa.get("name")
            if not it_sa_name:
                self.fail(f'the IT service account does not contain the "name" property: {it_sa}')

            self.assertEqual(rbac_sa_name, it_sa_name, "the names for the RBAC and IT models do not match")

            # Assert that the descriptions are the same.
            rbac_sa_description = rbac_sa.get("description")
            if not rbac_sa_description:
                self.fail(
                    f'the transformed RBAC service account does not contain the "description" property: {rbac_sa}'
                )

            it_sa_description = it_sa.get("description")
            if not it_sa_description:
                self.fail(f'the IT service account does not contain the "description" property: {it_sa}')

            self.assertEqual(
                rbac_sa_description, it_sa_description, "the descriptions for the RBAC and IT models do not match"
            )

            # Assert that the created by fields are the same.
            rbac_sa_created_by = rbac_sa.get("owner")
            if not rbac_sa_created_by:
                self.fail(f'the transformed RBAC service account does not contain the "owner" property: {rbac_sa}')

            it_sa_created_by = it_sa.get("createdBy")
            if not it_sa_created_by:
                self.fail(f'the IT service account does not contain the "createdBy" property: {it_sa}')

            self.assertEqual(
                rbac_sa_created_by,
                it_sa_created_by,
                "the owner and created by fields for the RBAC and IT models do not match",
            )

            # Assert that the created at fields are the same.
            rbac_sa_created_at = rbac_sa.get("time_created")
            if not rbac_sa_created_at:
                self.fail(
                    f'the transformed RBAC service account does not contain the "time_created" property: {rbac_sa}'
                )

            it_sa_created_at = it_sa.get("createdAt")
            if not it_sa_created_at:
                self.fail(f'the IT service account does not contain the "createdBy" property: {it_sa}')

            self.assertEqual(
                rbac_sa_created_at,
                it_sa_created_at,
                "the time created and created at fields for the RBAC and IT models do not match",
            )

    @mock.patch("management.principal.it_service.requests.get")
    def test_request_service_accounts_single_page(self, get: mock.Mock):
        """Test that the function under test can handle fetching a single page of service accounts from IT"""
        # Create the mocked response from IT.
        mocked_service_accounts = self._create_mock_it_service_accounts(5)

        get.__name__ = "get"
        get.return_value = mock.Mock(
            json=lambda: mocked_service_accounts,
            status_code=status.HTTP_200_OK,
        )

        bearer_token_mock = "bearer-token-mock"
        client_ids = [str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())]

        # Call the function under test.
        result: list[dict] = self.it_service.request_service_accounts(
            bearer_token=bearer_token_mock, client_ids=client_ids
        )

        # Build IT's URL for the function call's assertion.
        it_url = (
            f"{settings.IT_SERVICE_PROTOCOL_SCHEME}://{settings.IT_SERVICE_HOST}:{settings.IT_SERVICE_PORT}"
            f"{settings.IT_SERVICE_BASE_PATH}{IT_PATH_GET_SERVICE_ACCOUNTS}"
        )

        # Build the expected parameters to be seen in the "get" function's assertion call.
        parameters = {"first": 0, "max": 100, "clientId": client_ids}

        # Assert that the "get" function was called with the expected arguments.
        get.assert_called_with(
            url=it_url,
            headers={"Authorization": f"Bearer {bearer_token_mock}"},
            params=parameters,
            timeout=settings.IT_SERVICE_TIMEOUT_SECONDS,
        )

        # Assert that the payload is correct.
        self._assert_IT_to_RBAC_model_transformations(
            it_service_accounts=mocked_service_accounts, rbac_service_accounts=result
        )

    @mock.patch("management.principal.it_service.requests.get")
    def test_request_service_accounts_multiple_pages(self, get: mock.Mock):
        """Test that the function under test can handle fetching multiple pages from IT"""
        # Create the mocked response from IT.
        mocked_service_accounts = self._create_mock_it_service_accounts(300)

        # Make sure the "get" function returns multiple pages of service accounts.
        first_hundred_sas = mocked_service_accounts[0:100]
        second_hundred_sas = mocked_service_accounts[100:200]
        third_hundred_sas = mocked_service_accounts[200:300]

        get.__name__ = "get"
        get.side_effect = [
            mock.Mock(
                json=lambda: first_hundred_sas,
                status_code=status.HTTP_200_OK,
            ),
            mock.Mock(
                json=lambda: second_hundred_sas,
                status_code=status.HTTP_200_OK,
            ),
            mock.Mock(
                json=lambda: third_hundred_sas,
                status_code=status.HTTP_200_OK,
            ),
            mock.Mock(
                json=lambda: [],
                status_code=status.HTTP_200_OK,
            ),
        ]

        bearer_token_mock = "bearer-token-mock"
        # For multiple pages giving just three client IDs does not make sense, but we are going to give them anyway to
        # check that the parameter is included.
        client_ids = [str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())]

        # Call the function under test.
        result: list[dict] = self.it_service.request_service_accounts(
            bearer_token=bearer_token_mock, client_ids=client_ids
        )

        # Build IT's URL for the function call's assertion.
        it_url = (
            f"{settings.IT_SERVICE_PROTOCOL_SCHEME}://{settings.IT_SERVICE_HOST}:{settings.IT_SERVICE_PORT}"
            f"{settings.IT_SERVICE_BASE_PATH}{IT_PATH_GET_SERVICE_ACCOUNTS}"
        )

        # Assert that the "get" function is called with the expected arguments for the multiple pages.
        parameters_first_call = {"first": 0, "max": 100, "clientId": client_ids}
        parameters_second_call = {"first": 100, "max": 100, "clientId": client_ids}
        parameters_third_call = {"first": 200, "max": 100, "clientId": client_ids}
        parameters_fourth_call = {"first": 300, "max": 100, "clientId": client_ids}

        get.assert_has_calls(
            [
                mock.call(
                    url=it_url,
                    headers={"Authorization": f"Bearer {bearer_token_mock}"},
                    params=parameters_first_call,
                    timeout=settings.IT_SERVICE_TIMEOUT_SECONDS,
                ),
                mock.call(
                    url=it_url,
                    headers={"Authorization": f"Bearer {bearer_token_mock}"},
                    params=parameters_second_call,
                    timeout=settings.IT_SERVICE_TIMEOUT_SECONDS,
                ),
                mock.call(
                    url=it_url,
                    headers={"Authorization": f"Bearer {bearer_token_mock}"},
                    params=parameters_third_call,
                    timeout=settings.IT_SERVICE_TIMEOUT_SECONDS,
                ),
                mock.call(
                    url=it_url,
                    headers={"Authorization": f"Bearer {bearer_token_mock}"},
                    params=parameters_fourth_call,
                    timeout=settings.IT_SERVICE_TIMEOUT_SECONDS,
                ),
            ]
        )

        # Assert that the payload is correct.
        self._assert_IT_to_RBAC_model_transformations(
            it_service_accounts=mocked_service_accounts, rbac_service_accounts=result
        )

    @mock.patch("management.principal.it_service.requests.get")
    def test_request_service_accounts_unexpected_status_code(self, get: mock.Mock):
        """Test that the function under test raises an exception when an unexpected status code is received from IT"""
        get.__name__ = "get"
        get.return_value = mock.Mock(
            json=[],
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

        bearer_token_mock = "bearer-token-mock"
        client_ids = [str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())]

        # Call the function under test.
        try:
            self.it_service.request_service_accounts(bearer_token=bearer_token_mock, client_ids=client_ids)
            self.fail("the function under test should have raised an exception on an unexpected status code")
        except Exception as e:
            self.assertIsInstance(
                e,
                UnexpectedStatusCodeFromITError,
                "unexpected exception raised when the status code received from IT is unexpected",
            )

        # Build IT's URL for the function call's assertion.
        it_url = (
            f"{settings.IT_SERVICE_PROTOCOL_SCHEME}://{settings.IT_SERVICE_HOST}:{settings.IT_SERVICE_PORT}"
            f"{settings.IT_SERVICE_BASE_PATH}{IT_PATH_GET_SERVICE_ACCOUNTS}"
        )

        # Build the expected parameters to be seen in the "get" function's assertion call.
        parameters = {"first": 0, "max": 100, "clientId": client_ids}

        # Assert that the "get" function was called with the expected arguments.
        get.assert_called_with(
            url=it_url,
            headers={"Authorization": f"Bearer {bearer_token_mock}"},
            params=parameters,
            timeout=settings.IT_SERVICE_TIMEOUT_SECONDS,
        )

    @mock.patch("management.principal.it_service.requests.get")
    def test_request_service_accounts_connection_error(self, get: mock.Mock):
        """Test that the function under test raises an exception a connection error happens when connecting to IT"""
        get.__name__ = "get"
        get.side_effect = requests.exceptions.ConnectionError

        bearer_token_mock = "bearer-token-mock"
        client_ids = [str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())]

        # Call the function under test.
        try:
            self.it_service.request_service_accounts(bearer_token=bearer_token_mock, client_ids=client_ids)
            self.fail(
                "the function under test should have raised an exception when hitting a connection error with IT"
            )
        except Exception as e:
            self.assertIsInstance(
                e,
                requests.exceptions.ConnectionError,
                "unexpected exception raised when there is a connection error to IT",
            )

        # Build IT's URL for the function call's assertion.
        it_url = (
            f"{settings.IT_SERVICE_PROTOCOL_SCHEME}://{settings.IT_SERVICE_HOST}:{settings.IT_SERVICE_PORT}"
            f"{settings.IT_SERVICE_BASE_PATH}{IT_PATH_GET_SERVICE_ACCOUNTS}"
        )

        # Build the expected parameters to be seen in the "get" function's assertion call.
        parameters = {"first": 0, "max": 100, "clientId": client_ids}

        # Assert that the "get" function was called with the expected arguments.
        get.assert_called_with(
            url=it_url,
            headers={"Authorization": f"Bearer {bearer_token_mock}"},
            params=parameters,
            timeout=settings.IT_SERVICE_TIMEOUT_SECONDS,
        )

    @mock.patch("management.principal.it_service.requests.get")
    def test_request_service_accounts_timeout(self, get: mock.Mock):
        """Test that the function under test raises an exception a connection error happens when connecting to IT"""
        get.__name__ = "get"
        get.side_effect = requests.exceptions.Timeout

        bearer_token_mock = "bearer-token-mock"
        client_ids = [str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())]

        # Call the function under test.
        try:
            self.it_service.request_service_accounts(bearer_token=bearer_token_mock, client_ids=client_ids)
            self.fail("the function under test should have raised an exception when having a timeout with IT")
        except Exception as e:
            self.assertIsInstance(
                e,
                requests.exceptions.Timeout,
                "unexpected exception raised when there is a timeout with IT",
            )

        # Build IT's URL for the function call's assertion.
        it_url = (
            f"{settings.IT_SERVICE_PROTOCOL_SCHEME}://{settings.IT_SERVICE_HOST}:{settings.IT_SERVICE_PORT}"
            f"{settings.IT_SERVICE_BASE_PATH}{IT_PATH_GET_SERVICE_ACCOUNTS}"
        )

        # Build the expected parameters to be seen in the "get" function's assertion call.
        parameters = {"first": 0, "max": 100, "clientId": client_ids}

        # Assert that the "get" function was called with the expected arguments.
        get.assert_called_with(
            url=it_url,
            headers={"Authorization": f"Bearer {bearer_token_mock}"},
            params=parameters,
            timeout=settings.IT_SERVICE_TIMEOUT_SECONDS,
        )

    @mock.patch("management.principal.it_service.ITService._is_service_account_valid")
    def test_is_service_account_valid_by_username_client_id(self, _is_service_account_valid: mock.Mock):
        """Test that the function under test calls the underlying function with the unmodified client ID."""
        client_uuid = str(uuid.uuid4())
        user = User()

        self.it_service.is_service_account_valid_by_username(user=user, service_account_username=client_uuid)

        _is_service_account_valid.assert_called_with(user=user, client_id=client_uuid)

    @mock.patch("management.principal.it_service.ITService._is_service_account_valid")
    def test_is_service_account_valid_by_username_full(self, _is_service_account_valid: mock.Mock):
        """Test that the function under test calls the underlying function by stripping the service account prefix."""
        client_uuid = uuid.uuid4()
        username = f"service-account-{client_uuid}"
        user = User()

        self.it_service.is_service_account_valid_by_username(user=user, service_account_username=username)

        _is_service_account_valid.assert_called_with(user=user, client_id=str(client_uuid))

    @mock.patch("management.principal.it_service.ITService.request_service_accounts")
    def test_is_service_account_valid_bypass_it_calls(self, _):
        """Test that the function under test assumes service accounts to always be valid when bypassing IT calls."""
        original_bypass_it_calls_value = settings.IT_BYPASS_IT_CALLS
        try:
            settings.IT_BYPASS_IT_CALLS = True

            self.assertEqual(
                True,
                self.it_service._is_service_account_valid(user=User(), client_id="mocked-cid"),
                "when IT calls are bypassed, a service account should always be validated as if it existed",
            )
        finally:
            settings.IT_BYPASS_IT_CALLS = original_bypass_it_calls_value

    @mock.patch("management.principal.it_service.ITService.request_service_accounts")
    def test_is_service_account_valid_zero_results_from_it(self, request_service_accounts: mock.Mock):
        """Test that the function under test treats an empty result from IT as an invalid service account."""
        request_service_accounts.return_value = []
        user = User()
        user.bearer_token = "mocked-bt"

        self.assertEqual(
            False,
            self.it_service._is_service_account_valid(user=user, client_id="mocked-cid"),
            "when IT returns an empty array for the given client ID, the service account should be considered invalid",
        )

    @mock.patch("management.principal.it_service.ITService.request_service_accounts")
    def test_is_service_account_valid_one_matching_result_from_it(self, request_service_accounts: mock.Mock):
        """Test that the function under test positively validates the given service account if IT responds with that service account."""
        client_id = "client-id-123"
        request_service_accounts.return_value = [{"clientId": client_id}]
        user = User()
        user.bearer_token = "mocked-bt"

        self.assertEqual(
            True,
            self.it_service._is_service_account_valid(user=user, client_id=client_id),
            "when IT returns the requested service account via the client ID, the function under test should return True",
        )

    @mock.patch("management.principal.it_service.ITService.request_service_accounts")
    def test_is_service_account_valid_not_matching_result_from_it(self, request_service_accounts: mock.Mock):
        """Test that the function under test does not validate the given service account if IT does not return a response with a proper service account."""
        client_id = "client-id-123"
        request_service_accounts.return_value = [{"clientId": "different-client-id"}]
        user = User()
        user.bearer_token = "mocked-bt"

        self.assertEqual(
            False,
            self.it_service._is_service_account_valid(user=user, client_id=client_id),
            "when IT returns a service account which doesn't match the provided client ID, the function under test should return False",
        )

    @mock.patch("management.principal.it_service.ITService.request_service_accounts")
    def test_is_service_account_valid_multiple_results_from_it(self, request_service_accounts: mock.Mock):
        """Test that the function under retunrs False when IT returns multiple service accounts for a single client ID."""
        request_service_accounts.return_value = [{}, {}]
        user = User()
        user.bearer_token = "mocked-bt"

        self.assertEqual(
            False,
            self.it_service._is_service_account_valid(user=user, client_id="mocked_cid"),
            "when IT returns more service accounts than the ones requested, the function under test should return False",
        )

    def test_username_is_service_account(self) -> None:
        """Test that the username is correctly identified as a service account."""
        username = f"service-account-{uuid.uuid4()}"
        self.assertEqual(
            ITService.is_username_service_account(username),
            True,
            f"the given username '{username}' should have been identified as a service account username",
        )

    def test_username_is_not_service_account(self) -> None:
        """Test that the provided usernames are correctly identified as not service accounts."""
        usernames: list[str] = [
            "foo",
            "bar",
            f"serivce-account-{uuid.uuid4()}",
            f"service-acount-{uuid.uuid4()}",
            str(uuid.uuid4()),
        ]

        for username in usernames:
            self.assertEqual(
                ITService.is_username_service_account(username),
                False,
                f"the given username '{username}' should have not been identified as a service account username",
            )

    def test_extract_client_id_service_account_username(self) -> None:
        """Test that the client ID is correctly extracted from the service account's username"""
        client_id = uuid.uuid4()

        # Call the function under test with just the client ID. It should return it as is.
        self.assertEqual(
            client_id,
            ITService.extract_client_id_service_account_username(username=str(client_id)),
            "the client ID should be returned when it is passed to the function under test",
        )

        # Call the function under test with the whole prefix, and check that the client ID is correctly identified.
        self.assertEqual(
            client_id,
            ITService.extract_client_id_service_account_username(username=f"service-account-{client_id}"),
            "the client ID was not correctly extracted from a full username",
        )

        # Call the function under test with an invalid username which contains a bad formed UUID.
        try:
            ITService.extract_client_id_service_account_username(username="abcde")
            self.fail(
                "when providing an invalid UUID as the client ID to be extracted, the function under test should raise an error"
            )
        except serializers.ValidationError as ve:
            self.assertEqual(
                "unable to extract the client ID from the service account's username because the provided UUID is invalid",
                str(ve.detail.get("detail")),
                "unexpected error message when providing an invalid UUID as the client ID",
            )
