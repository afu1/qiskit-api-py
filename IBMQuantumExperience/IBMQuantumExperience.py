"""
    IBM Quantum Experience Python API Client
"""
try:
    import simplejson as json
except ImportError:
    import json
import time
import logging
from datetime import datetime
import sys
import traceback
import requests
import re

logging.basicConfig()
CLIENT_APPLICATION = 'qiskit-api-py'


class _Credentials(object):
    """
    The Credential class to manage the tokens
    """
    config_base = {'url': 'https://quantumexperience.ng.bluemix.net/api'}

    def __init__(self, token, config=None, verify=True):
        self.token_unique = token
        self.verify = verify
        self.config = config
        if not verify:
            import requests.packages.urllib3 as urllib3
            urllib3.disable_warnings()
            print('-- Ignoring SSL errors.  This is not recommended --')
        if self.config and ("url" not in self.config):
            self.config["url"] = self.config_base["url"]
        elif not self.config:
            self.config = self.config_base

        self.data_credentials = {}
        if token:
            self.obtain_token(config=self.config)
        else:
            access_token = self.config.get('access_token', None)
            if access_token:
                user_id = self.config.get('user_id', None)
                if access_token:
                    self.set_token(access_token)
                if user_id:
                    self.set_user_id(user_id)
            else:
                self.obtain_token(config=self.config)

    def obtain_token(self, config=None):
        """Obtain the token to access to QX Platform.

        Raises:
            CredentialsError: when token is invalid.
        """
        client_application = CLIENT_APPLICATION
        if self.config and ("client_application" in self.config):
            client_application += ':' + self.config["client_application"]
        headers = {'x-qx-client-application': client_application}
        if self.token_unique:
            self.data_credentials = requests.post(str(self.config.get('url') +
                                                  "/users/loginWithToken"),
                                                  data={'apiToken':
                                                        self.token_unique},
                                                  verify=self.verify,
                                                  headers=headers).json()
        elif config and ("email" in config) and ("password" in config):
            email = config.get('email', None)
            password = config.get('password', None)
            credentials = {
                'email': email,
                'password': password
            }
            self.data_credentials = requests.post(str(self.config.get('url') +
                                                  "/users/login"),
                                                  data=credentials,
                                                  verify=self.verify,
                                                  headers=headers).json()
        else:
            raise CredentialsError('invalid token')

        if self.get_token() is None:
            raise CredentialsError('invalid token')

    def get_token(self):
        """
        Get Authenticated Token to connect with QX Platform
        """
        return self.data_credentials.get('id', None)

    def get_user_id(self):
        """
        Get User Id in QX Platform
        """
        return self.data_credentials.get('userId', None)

    def get_config(self):
        """
        Get Configuration setted to connect with QX Platform
        """
        return self.config

    def set_token(self, access_token):
        """
        Set Access Token to connect with QX Platform API
        """
        self.data_credentials['id'] = access_token

    def set_user_id(self, user_id):
        """
        Set Access Token to connect with QX Platform API
        """
        self.data_credentials['userId'] = user_id


class _Request(object):
    """
    The Request class to manage the methods
    """
    def __init__(self, token, config=None, verify=True, retries=5,
                 timeout_interval=1.0):
        self.verify = verify
        self.client_application = CLIENT_APPLICATION
        self.config = config
        if self.config and ("client_application" in self.config):
            self.client_application += ':' + self.config["client_application"]
        self.credential = _Credentials(token, self.config, verify)
        self.log = logging.getLogger(__name__)
        if not isinstance(retries, int):
            raise TypeError('post retries must be positive integer')
        self.retries = retries
        self.timeout_interval = timeout_interval
        self.result = None
        self._max_qubit_error_re = re.compile(
            r".*registers exceed the number of qubits, "
            r"it can\'t be greater than (\d+).*")

    def check_token(self, respond):
        """
        Check is the user's token is valid
        """
        if respond.status_code == 401:
            self.credential.obtain_token(config=self.config)
            return False
        return True

    def post(self, path, params='', data=None):
        """
        POST Method Wrapper of the REST API
        """
        self.result = None
        data = data or {}
        headers = {'Content-Type': 'application/json',
                   'x-qx-client-application': self.client_application}
        url = str(self.credential.config['url'] + path + '?access_token=' +
                  self.credential.get_token() + params)
        retries = self.retries
        while retries > 0:
            respond = requests.post(url, data=data, headers=headers,
                                    verify=self.verify)
            if not self.check_token(respond):
                respond = requests.post(url, data=data, headers=headers,
                                        verify=self.verify)

            if self._response_good(respond):
                if self.result:
                    return self.result
                else:
                    return respond.json()
            else:
                retries -= 1
                time.sleep(self.timeout_interval)
        # timed out
        raise ApiError(usr_msg='Failed to get proper ' +
                       'response from backend.')

    def put(self, path, params='', data=None):
        """
        PUT Method Wrapper of the REST API
        """
        self.result = None
        data = data or {}
        headers = {'Content-Type': 'application/json',
                   'x-qx-client-application': self.client_application}
        url = str(self.credential.config['url'] + path + '?access_token=' +
                  self.credential.get_token() + params)
        retries = self.retries
        while retries > 0:
            respond = requests.put(url, data=data, headers=headers,
                                    verify=self.verify)
            if not self.check_token(respond):
                respond = requests.put(url, data=data, headers=headers,
                                        verify=self.verify)
            if self._response_good(respond):
                if self.result:
                    return self.result
                else:
                    return respond.json()
            else:
                retries -= 1
                time.sleep(self.timeout_interval)
        # timed out
        raise ApiError(usr_msg='Failed to get proper ' +
                       'response from backend.')

    def get(self, path, params='', with_token=True):
        """
        GET Method Wrapper of the REST API
        """
        self.result = None
        access_token = ''
        if with_token:
            access_token = self.credential.get_token() or ''
            if access_token:
                access_token = '?access_token=' + str(access_token)
        url = self.credential.config['url'] + path + access_token + params
        retries = self.retries
        headers = {'x-qx-client-application': self.client_application}
        while retries > 0:  # Repeat until no error
            respond = requests.get(url, verify=self.verify, headers=headers)
            if not self.check_token(respond):
                respond = requests.get(url, verify=self.verify,
                                       headers=headers)
            if self._response_good(respond):
                if self.result:
                    return self.result
                else:
                    return respond.json()
            else:
                retries -= 1
                time.sleep(self.timeout_interval)
        # timed out
        raise ApiError(usr_msg='Failed to get proper ' +
                       'response from backend.')

    def delete(self, path, params=''):
        """
        PUT Method Wrapper of the REST API
        """
        self.result = None
        headers = {'Content-Type': 'application/json',
                   'x-qx-client-application': self.client_application}
        url = str(self.credential.config['url'] + path + '?access_token=' +
                  self.credential.get_token() + params)
        retries = self.retries
        while retries > 0:
            respond = requests.delete(url, headers=headers,
                                    verify=self.verify)
            if not self.check_token(respond):
                respond = requests.delete(url, headers=headers,
                                        verify=self.verify)
            if self._response_good(respond):
                if self.result:
                    return self.result
                else:
                    return respond.json()
            else:
                retries -= 1
                time.sleep(self.timeout_interval)
        # timed out
        raise ApiError(usr_msg='Failed to get proper ' +
                       'response from backend.')

    def _response_good(self, respond):
        """check response

        Args:
            respond (str): HTTP response.

        Returns:
            bool: True if the response is good, else False.

        Raises:
            ApiError: response isn't formatted properly.
        """
        ok_codes = [200, 201, 204]
        if int(respond.status_code) not in ok_codes:
            self.log.warning('Got a {} code response to {}: {}'.format(
                respond.status_code,
                respond.url,
                respond.text))
            return self._parse_response(respond)
        try:
            if respond.status_code == 204:  # not content as response but ok
                self.result = {"status": "ok"}
            else:
                self.result = respond.json()
        except:
            usr_msg = 'device server returned unexpected http response'
            dev_msg = usr_msg + ': ' + respond.text
            raise ApiError(usr_msg=usr_msg, dev_msg=dev_msg)
        if not isinstance(self.result, (list, dict)):
            msg = ('JSON not a list or dict: url: {0},'
                   'status: {1}, reason: {2}, text: {3}')
            raise ApiError(
                usr_msg=msg.format(respond.url,
                                   respond.status_code,
                                   respond.reason, respond.text))
        if ('error' not in self.result or
                ('status' not in self.result['error'] or
                 self.result['error']['status'] != 400)):
            return True
        else:
            self.log.warning("Got a 400 code JSON response to %s", respond.url)
            return False

    def _parse_response(self, respond):
        """parse text of response for HTTP errors

        This parses the text of the response to decide whether to
        retry request or raise exception. At the moment this only
        detects an exception condition.

        Args:
            respond (Response): requests.Response object

        Returns:
            bool: False if the request should be retried, True
                if not.

        Raises:
            RegisterSizeError
        """
        # convert error messages into exceptions
        mobj = self._max_qubit_error_re.match(respond.text)
        if mobj:
            raise RegisterSizeError(
                'device register size must be <= {}'.format(mobj.group(1)))
        return True


class IBMQuantumExperience(object):
    """
    The Connector Class to do request to QX Platform
    """
    __names_backend_ibmqxv2 = ['ibmqx5qv2', 'ibmqx2', 'qx5qv2', 'qx5q', 'real']
    __names_backend_ibmqxv3 = ['ibmqx3']
    __names_backend_simulator = ['simulator', 'sim_trivial_2',
                                 'ibmqx_qasm_simulator']

    def __init__(self, token=None, config=None, verify=True):
        """ If verify is set to false, ignore SSL certificate errors """
        self.req = _Request(token, config=config, verify=verify)

    def _check_backend(self, backend, endpoint):
        """
        Check if the name of a backend is valid to run in QX Platform
        """
        # First check against hacks for old backend names
        original_backend = backend
        backend = backend.lower()
        if endpoint == 'experiment':
            if backend in self.__names_backend_ibmqxv2:
                return 'real'
            elif backend in self.__names_backend_ibmqxv3:
                return 'ibmqx3'
            elif backend in self.__names_backend_simulator:
                return 'sim_trivial_2'
        elif endpoint == 'job':
            if backend in self.__names_backend_ibmqxv2:
                return 'ibmqx2'
            elif backend in self.__names_backend_ibmqxv3:
                return 'ibmqx3'
            elif backend in self.__names_backend_simulator:
                return 'simulator'
        elif endpoint == 'status':
            if backend in self.__names_backend_ibmqxv2:
                return 'ibmqx2'
            elif backend in self.__names_backend_ibmqxv3:
                return 'ibmqx3'
            elif backend in self.__names_backend_simulator:
                return 'ibmqx_qasm_simulator'
        elif endpoint == 'calibration':
            if backend in self.__names_backend_ibmqxv2:
                return 'ibmqx2'
            elif backend in self.__names_backend_ibmqxv3:
                return 'ibmqx3'
            elif backend in self.__names_backend_simulator:
                return 'ibmqx_qasm_simulator'

        # Check for new-style backends
        backends = self.available_backends()
        for backend in backends:
            if backend['name'] == original_backend:
                if backend.get('simulator', False):
                    return 'chip_simulator'
                else:
                    return original_backend
        # backend unrecognized
        return None

    def check_credentials(self):
        """
        Check if the user has permission in QX platform
        """
        return bool(self.req.credential.get_token())

    def get_execution(self, id_execution, access_token=None, user_id=None):
        """
        Get a execution, by its id
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            raise CredentialsError('credentials invalid')
        execution = self.req.get('/Executions/' + id_execution)
        if execution["codeId"]:
            execution['code'] = self.get_code(execution["codeId"])
        return execution

    def get_result_from_execution(self, id_execution, access_token=None, user_id=None):
        """
        Get the result of a execution, by the execution id
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            raise CredentialsError('credentials invalid')
        execution = self.req.get('/Executions/' + id_execution)
        result = {}
        if "result" in execution and "data" in execution["result"]:
            if execution["result"]["data"].get('p', None):
                result["measure"] = execution["result"]["data"]["p"]
            if execution["result"]["data"].get('valsxyz', None):
                result["bloch"] = execution["result"]["data"]["valsxyz"]
            if "additionalData" in execution["result"]["data"]:
                ad_aux = execution["result"]["data"]["additionalData"]
                result["extraInfo"] = ad_aux
            if "calibration" in execution:
                result["calibration"] = execution["calibration"]
            if execution["result"]["data"].get('cregLabels', None):
                result["creg_labels"] = execution["result"]["data"]["cregLabels"]
            if execution["result"]["data"].get('time', None):
                result["time_taken"] = execution["result"]["data"]["time"]

        return result

    def get_code(self, id_code, access_token=None, user_id=None):
        """
        Get a code, by its id
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            raise CredentialsError('credentials invalid')
        code = self.req.get('/Codes/' + id_code)
        executions = self.req.get('/Codes/' + id_code + '/executions',
                                  '&filter={"limit":3}')
        if isinstance(executions, list):
            code["executions"] = executions
        return code

    def get_image_code(self, id_code, access_token=None, user_id=None):
        """
        Get the image of a code, by its id
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            raise CredentialsError('credentials invalid')
        return self.req.get('/Codes/' + id_code + '/export/png/url')

    def get_last_codes(self, access_token=None, user_id=None):
        """
        Get the last codes of the user
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            raise CredentialsError('credentials invalid')
        last = '/users/' + self.req.credential.get_user_id() + '/codes/lastest'
        return self.req.get(last, '&includeExecutions=true')['codes']

    def run_experiment(self, qasm, backend='simulator', shots=1, name=None,
                       seed=None, timeout=60, access_token=None, user_id=None):
        """
        Execute an experiment
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            raise CredentialsError('credentials invalid')

        backend_type = self._check_backend(backend, 'experiment')
        if not backend_type:
            raise BadBackendError(backend)

        if backend not in self.__names_backend_simulator and seed:
            raise ApiError('seed not allowed for'
                           ' non-simulator backend "{}"'.format(backend))

        name = name or 'Experiment #{:%Y%m%d%H%M%S}'.format(datetime.now())
        qasm = qasm.replace('IBMQASM 2.0;', '').replace('OPENQASM 2.0;', '')
        data = json.dumps({'qasm': qasm, 'codeType': 'QASM2', 'name': name})

        if seed and len(str(seed)) < 11 and str(seed).isdigit():
            params = '&shots={}&seed={}&deviceRunType={}'.format(shots, seed,
                                                                 backend_type)
            execution = self.req.post('/codes/execute', params, data)
        elif seed:
            raise ApiError('invalid seed ({}), seeds can have'
                           ' a maximum length of 10 digits'.format(seed))
        else:
            params = '&shots={}&deviceRunType={}'.format(shots, backend_type)
            execution = self.req.post('/codes/execute', params, data)
        respond = {}
        try:
            status = execution["status"]["id"]
            id_execution = execution["id"]
            result = {}
            respond["status"] = status
            respond["idExecution"] = id_execution
            respond["idCode"] = execution["codeId"]

            if 'infoQueue' in execution:
                respond['infoQueue'] = execution['infoQueue']

            if status == "DONE":
                if "result" in execution and "data" in execution["result"]:
                    if "additionalData" in execution["result"]["data"]:
                        ad_aux = execution["result"]["data"]["additionalData"]
                        result["extraInfo"] = ad_aux
                    if execution["result"]["data"].get('p', None):
                        result["measure"] = execution["result"]["data"]["p"]
                    if execution["result"]["data"].get('valsxyz', None):
                        valsxyz = execution["result"]["data"]["valsxyz"]
                        result["bloch"] = valsxyz
                    respond["result"] = result
                    respond.pop('infoQueue', None)

                    return respond
            elif status == "ERROR":
                respond.pop('infoQueue', None)
                return respond
            else:
                if timeout:
                    for _ in range(1, timeout):
                        print("Waiting for results...")
                        result = self.get_result_from_execution(id_execution)
                        if result:
                            respond["status"] = 'DONE'
                            respond["result"] = result
                            respond["calibration"] = result["calibration"]
                            del result["calibration"]
                            respond.pop('infoQueue', None)
                            return respond
                        else:
                            time.sleep(2)
                    return respond
                else:
                    return respond
        except Exception:
            respond["error"] = execution
            return respond

    def run_job(self, qasms, backend='simulator', shots=1,
                max_credits=3, seed=None, access_token=None, user_id=None):
        """
        Execute a job
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}
        for qasm in qasms:
            qasm['qasm'] = qasm['qasm'].replace('IBMQASM 2.0;', '')
            qasm['qasm'] = qasm['qasm'].replace('OPENQASM 2.0;', '')
        data = {'qasms': qasms,
                'shots': shots,
                'maxCredits': max_credits,
                'backend': {}}

        backend_type = self._check_backend(backend, 'job')

        if not backend_type:
            raise BadBackendError(backend)

        if seed and len(str(seed)) < 11 and str(seed).isdigit():
            data['seed'] = seed
        elif seed:
            return {"error": "Not seed allowed. Max 10 digits."}

        data['backend']['name'] = backend_type
        job = self.req.post('/Jobs', data=json.dumps(data))
        return job

    def get_job(self, id_job, access_token=None, user_id=None):
        """
        Get the information about a job, by its id
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            respond = {}
            respond["status"] = 'Error'
            respond["error"] = "Not credentials valid"
            return respond
        if not id_job:
            respond = {}
            respond["status"] = 'Error'
            respond["error"] = "Job ID not specified"
            return respond
        job = self.req.get('/Jobs/' + id_job)

        # To remove result object and add the attributes to data object
        if 'qasms' in job:
            for qasm in job['qasms']:
                if ('result' in qasm) and ('data' in qasm['result']):
                    qasm['data'] = qasm['result']['data']
                    del qasm['result']['data']
                    for key in qasm['result']:
                        qasm['data'][key] = qasm['result'][key]
                    del qasm['result']

        return job

    def get_jobs(self, limit=50, access_token=None, user_id=None):
        """
        Get the information about the user jobs
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}
        jobs = self.req.get('/Jobs', '&filter={"limit":' + str(limit) + '}')
        return jobs

    def backend_status(self, backend='ibmqx4', access_token=None, user_id=None):
        """
        Get the status of a chip
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        backend_type = self._check_backend(backend, 'status')
        if not backend_type:
            raise BadBackendError(backend)

        status = self.req.get('/Backends/' + backend_type + '/queue/status',
                              with_token=False)

        ret = {}
        if 'state' in status:
            ret['available'] = bool(status['state'])
        if 'busy' in status:
            ret['busy'] = bool(status['busy'])
        if 'lengthQueue' in status:
            ret['pending_jobs'] = status['lengthQueue']
        
        ret['backend'] = backend_type

        return ret

    def backend_calibration(self, backend='ibmqx4', access_token=None, user_id=None):
        """
        Get the calibration of a real chip
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            raise CredentialsError('credentials invalid')

        backend_type = self._check_backend(backend, 'calibration')

        if not backend_type:
            raise BadBackendError(backend)

        if backend_type in self.__names_backend_simulator:
            ret = {}
            ret["backend"] = backend_type
            ret["calibrations"] = None
            return ret

        ret = self.req.get('/Backends/' + backend_type + '/calibration')
        ret["backend"] = backend_type
        return ret

    def backend_parameters(self, backend='ibmqx4', access_token=None, user_id=None):
        """
        Get the parameters of calibration of a real chip
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            raise CredentialsError('credentials invalid')

        backend_type = self._check_backend(backend, 'calibration')

        if not backend_type:
            raise BadBackendError(backend)

        if backend_type in self.__names_backend_simulator:
            ret = {}
            ret["backend"] = backend_type
            ret["parameters"] = None
            return ret

        ret = self.req.get('/Backends/' + backend_type + '/parameters')
        ret["backend"] = backend_type
        return ret

    def available_backends(self, access_token=None, user_id=None):
        """
        Get the backends available to use in the QX Platform
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            raise CredentialsError('credentials invalid')
        else:
            return [backend for backend in self.req.get('/Backends')
                    if backend.get('status') == 'on']

    def available_backend_simulators(self, access_token=None, user_id=None):
        """
        Get the backend simulators available to use in the QX Platform
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            raise CredentialsError('credentials invalid')
        else:
            return [backend for backend in self.req.get('/Backends')
                    if backend.get('status') == 'on' and
                    backend.get('simulator') is True]

    def get_my_credits(self, raw=None, access_token=None, user_id=None):
        """
        Get the the credits by user to use in the QX Platform
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            raise CredentialsError('credentials invalid')
        else:
            user_data_url = '/users/' + self.req.credential.get_user_id()
            user_data = self.req.get(user_data_url)
            if "credit" in user_data:
                if "promotionalCodesUsed" in user_data["credit"]:
                    del user_data["credit"]["promotionalCodesUsed"]
                if "lastRefill" in user_data["credit"]:
                    del user_data["credit"]["lastRefill"]
                return user_data["credit"]
            return {}

    # Admins Methods
    '''
    Methods to run by admins, to manage users
    '''

    def _get_user_id_from_email(self, email):
        """
        Get a user id from email
        """
        where = {
            "where": {
                "email": email
            }
        }

        params = "&filter="+json.dumps(where)

        user = self.req.get('/users/findOne', params)
        if user and ("id" in user):
            return user["id"]
        return None

    def _get_user_group_id_from_name(self, name, access_token=None,
                                     user_id=None):
        """
        Get a user group id from user group name
        """
        if name is None:
            return None
        user_groups = self.get_user_groups(access_token, user_id)
        for group in user_groups:
            if ("name" in group) and (group['name'].lower() == name.lower()):
                return group['id']
        return None

    def _get_topology_id_from_name(self, name, access_token=None,
                                   user_id=None):
        """
        Get a topology id from topology name
        """
        topology = self.get_topology(name, access_token, user_id)
        if "id" in topology:
            return topology['id']
        return None

    def get_user(self, email):
        """
        Get a user from email
        """
        where = {
            "where": {
                "email": email
            }
        }

        params = "&filter="+json.dumps(where)

        user = self.req.get('/users/findOne', params)
        return user

    def create_user(self, name, email, password, institution,
                    access_token=None, user_id=None):
        """
        Create a user by admin
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        data = {
            'firstName': name,
            'email': email,
            'password': password,
            'institution': institution
        }

        user = self.req.post('/users/createByAdmin', data=json.dumps(data))
        return user

    def edit_user(self, email, password=None, institution=None,
                  blocked=None, credits=None, usernamepublic=None,
                  access_token=None, user_id=None):
        """
        Edit a user by admin
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        user = self.get_user(email)

        if not user:
            return {"error": "Not user found"}

        user_id = user["id"]
        user_credits = user["credit"]

        data = {}

        if institution:
            data["institution"] = institution
        if blocked or (blocked is False):
            data["blocked"] = blocked
        if credits:
            data["credit"] = user_credits
            data["credit"]["remaining"] = credits
        if usernamepublic:
            data["usernamePublic"] = usernamepublic
        if password:
            data["password"] = password

        user = self.req.put('/users/'+user_id, data=json.dumps(data))
        return user

    def create_user_group(self, name, description, is_general=False, 
                          access_token=None, user_id=None):
        """
        Create an user group to asign to users
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        data = {
            "name": name,
            "description": description,
            "isGeneral": is_general,
            "ownerId": self.req.credential.get_user_id()
        }

        user_group = self.req.post('/UserGroups', data=json.dumps(data))
        return user_group

    def edit_user_group(self, name, description, is_general=False, 
                        access_token=None, user_id=None):
        """
        Create an user group to asign to users
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        id_user_group = self.get_user_group(name)["id"]

        data = {
            "description": description,
            "isGeneral": is_general,
        }

        user_group = self.req.put('/UserGroups/' + id_user_group,
                                  data=json.dumps(data))
        return user_group

    def get_user_group(self, name, access_token=None, user_id=None):
        """
        Get user group to asign to users
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        where = {
            "where": {
                "name": name
            }
        }

        params = "&filter="+json.dumps(where)

        user_group = self.req.get('/UserGroups/findOne', params)
        return user_group

    def get_user_groups(self, access_token=None, user_id=None):
        """
        Get user groups to asign to users
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        user_groups = self.req.get('/UserGroups')
        return user_groups

    def set_user_group(self, email, name_user_group,
                       access_token=None, user_id=None):
        """
        Set user group to User
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        id_user_group = self._get_user_group_id_from_name(name_user_group,
                                                          access_token=access_token, user_id=user_id)  # noqa

        id_user = self._get_user_id_from_email(email)
        
        if id_user_group and id_user:
            user = self.req.put('/users/' + str(id_user) +
                                '/groups/rel/' + str(id_user_group))
            return user
        else:
            raise ApiError(usr_msg='User group doesnt exist ' +
                           name_user_group)

    def unset_user_group(self, email, name_user_group,
                         access_token=None, user_id=None):
        """
        Unset user group to User
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        id_user_group = self._get_user_group_id_from_name(name_user_group,
                                                          access_token=access_token, user_id=user_id)  # noqa

        id_user = self._get_user_id_from_email(email)
        
        if id_user_group and id_user:
            user = self.req.delete('/users/' + str(id_user) +
                                   '/groups/rel/' + str(id_user_group))
            return user
        else:
            raise ApiError(usr_msg='User group or user doesnt exist ' +
                           name_user_group + ":" + email)

    def get_topologies(self, access_token=None, user_id=None):
        """
        Get topologies used in the backends
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        topologies = self.req.get('/Topologies')
        return topologies

    def get_topology(self, name, access_token=None, user_id=None):
        """
        Get topology by name
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        where = {
            "where": {
                "name.en": name
            }
        }

        params = "&filter="+json.dumps(where)

        topology = self.req.get('/Topologies/findOne', params)

        return topology

    def create_topology(self, name, description, adjacency_matrix,
                        qubits, execution_types, is_simulator=False,
                        is_hidden=False, tasks_queue=None,
                        results_queue=None, device_status_queue=None,
                        status_queue=None, is_default=False,
                        qasm_header="IBMQASM 2.0;\n", picture_url=None,
                        access_token=None, user_id=None):
        """
        Create topology
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        e_types = []
        if isinstance(execution_types, (list, tuple)):
            for e_type in execution_types:
                if (e_type.lower() == 'simulator'):
                    e_types.append('sim_trivial_2')
                elif (e_type.lower() == 'real'):
                    e_types.append('real')
                else:
                    return {"error": "Invalid Execution Type, only allowed " +
                                     "'simulator' and 'real': " + e_type}
        else:
            return {"error": "Not valid execution types"}

        if (len(e_types) == 0):
            return {"error": "Not valid execution types"}

        data = {
            "name": {
                "en": name
            },
            "description": {
                "en": description
            },
            "topology": {
                "adjacencyMatrix": adjacency_matrix,
                "qasmHeader": qasm_header
            },
            "qubits": qubits,
            "executionTypes": e_types,
            "attributes": {
                "queues": {},
                "status": {}
            },
            "default": is_default,
            "isSimulator": is_simulator,
            "isHidden": is_hidden
        }

        if picture_url:
            data["picture"] = picture_url

        if tasks_queue:
            data["attributes"]["queues"]["tasks"] = tasks_queue
        else:
            data["attributes"]["queues"]["tasks"] = "tasks-" + name

        if results_queue:
            data["attributes"]["queues"]["results"] = results_queue
        else:
            data["attributes"]["queues"]["results"] = "results-" + name

        if device_status_queue:
            data["attributes"]["status"]["device"] = device_status_queue
        else:
            data["attributes"]["status"]["device"] = "status-device-" + name

        if status_queue:
            data["attributes"]["status"]["queue"] = status_queue
        else:
            data["attributes"]["status"]["queue"] = "status-queue-" + name

        topology = self.req.post('/Topologies', data=json.dumps(data))

        return topology

    def edit_topology(self, name, description=None, adjacency_matrix=None,
                      qubits=None, execution_types=None, is_simulator=None,
                      is_hidden=None, tasks_queue=None,
                      results_queue=None, device_status_queue=None,
                      status_queue=None, is_default=None,
                      qasm_header=None, picture_url=None,
                      access_token=None, user_id=None):
        """
        Edit topology by name
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        data = self.get_topology(name)

        if not data:
            return {"error": "Not topology found: " + name}

        e_types = None
        if execution_types is not None:
            e_types = []
            if isinstance(execution_types, (list, tuple)):
                for e_type in execution_types:
                    if (e_type.lower() == 'simulator'):
                        e_types.append('sim_trivial_2')
                    elif (e_type.lower() == 'real'):
                        e_types.append('real')
                    else:
                        return {"error": "Invalid Execution Type" +
                                         ", only allowed" +
                                         " 'simulator' and 'real': " + e_type}
            else:
                return {"error": "Not valid execution types"}

            if (len(e_types) == 0):
                return {"error": "Not valid execution types"}

        if description:
            data["description"] = {
                "en": description
            }

        if adjacency_matrix:
            data["topology"]["adjacencyMatrix"] = adjacency_matrix

        if qubits:
            data["qubits"] = qubits
            
        if execution_types is not None:
            data["executionTypes"] = e_types

        if is_simulator is not None:
            data["isSimulator"] = is_simulator

        if is_hidden is not None:
            data["isHidden"] = is_hidden

        if tasks_queue:
            data["attributes"]["queues"]["tasks"] = tasks_queue
        else:
            data["attributes"]["queues"]["tasks"] = "tasks-" + name

        if results_queue:
            data["attributes"]["queues"]["results"] = results_queue
        else:
            data["attributes"]["queues"]["results"] = "results-" + name

        if device_status_queue:
            data["attributes"]["status"]["device"] = device_status_queue
        else:
            data["attributes"]["status"]["device"] = "status-device-" + name

        if status_queue:
            data["attributes"]["status"]["queue"] = status_queue
        else:
            data["attributes"]["status"]["queue"] = "status-queue-" + name

        if is_default is not None:
            data["default"] = is_default

        if qasm_header:
            data["qasmHeader"] = qasm_header

        if picture_url:
            data["picture"] = picture_url

        topology = self.req.put('/Topologies/' + data["id"],
                                data=json.dumps(data))

        return topology

    def get_user_groups_to_topology(self, name_topology=None,
                                    name_user_group=None,
                                    access_token=None, user_id=None):
        """
        Get the relations between an user group to a topology
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        id_topology = self._get_topology_id_from_name(name_topology,
                                                      access_token=access_token, user_id=user_id)  # noqa

        id_user_group = self._get_user_group_id_from_name(name_user_group)

        params = ''
        if id_user_group or id_topology:
            where = {
                "where": {}
            }

            if id_topology:
                where["where"]["topologyId"] = id_topology
            if id_user_group:
                where["where"]["userGroupId"] = id_user_group

            params = "&filter="+json.dumps(where)
        tugs = self.req.get('/TopologyUserGroups/', params)
        return tugs

    def set_user_group_to_topology(self, name_topology, name_user_group,
                                   can_always_run=False,
                                   access_token=None, user_id=None):
        """
        Set an user group to a topology
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        id_topology = self._get_topology_id_from_name(name_topology,
                                                      access_token=access_token, user_id=user_id)  # noqa

        id_user_group = self._get_user_group_id_from_name(name_user_group)
        
        if id_user_group and id_topology:
            data = {
                "userGroupId": id_user_group,
                "topologyId": id_topology,
                "canAlwaysRun": can_always_run
            }
            tug = self.req.post('/TopologyUserGroups/', data=json.dumps(data))
            return tug
        else:
            raise ApiError(usr_msg='User group or topology doesnt exist ' +
                           name_user_group + ":" + name_topology)

    def unset_user_group_to_topology(self, name_topology=None,
                                     name_user_group=None,
                                     access_token=None, user_id=None):
        """
        Unset an user group to a topology
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        tugs = self.get_user_groups_to_topology(name_topology, name_user_group)

        deleted = 0
        for tug in tugs:
            if "id" in tug:
                unset = self.req.delete('/TopologyUserGroups/' + tug["id"])
                if "count" in unset:
                    deleted += unset["count"]
        return {"count": deleted}

    def get_backend_by_name(self, name,
                            access_token=None, user_id=None):
        """
        Create a backend by admin
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}
        
        where = {
            "where": {
                "name": name
            }
        }
        params = "&filter="+json.dumps(where)

        backend = self.req.get('/Devices/findOne', params)
        return backend

    def get_backends(self, access_token=None, user_id=None):
        """
        Create a backend by admin
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}
        
        backends = self.req.get('/Devices')
        return backends

    def create_backend(self, name, serial_number, type_device, version,
                       chip_name, url_details, name_topology, status='On',
                       description=None, gate_set=None, date_online=None,
                       access_token=None, user_id=None):
        """
        Create a backend by admin
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        id_topology = self._get_topology_id_from_name(name_topology)

        if not id_topology:
            return {"error": "Not topology valid: " + name_topology}

        if ((type_device != 'Simulator') and (type_device != 'Real')):
            return {"error": "Not type of the device valid: " + type_device +
                    ". Only allowed 'Simulator' or 'Real'"}

        if ((status != 'On') and (status != 'Off')):
            return {"error": "Not status of the device valid: " + type_device +
                    ". Only allowed 'On' or 'Off'"}

        if date_online:
            try:
                datetime.strptime(date_online, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                return {"error": "Not date_online valid in ISO Format" +
                        " (YYYY-MM-DDTHH:mm:ss.sssZ): " + date_online}

        data = {
            'name': name,
            'serialNumber': serial_number,
            'type': type_device,
            'version': version,
            'chipName': chip_name,
            'docUrl': url_details,
            'status': status,
            'onlineDate': date_online,
            'topologyId': id_topology,
            'description': description,
            'gateSet': gate_set
        }

        backend = self.req.post('/Devices', data=json.dumps(data))
        return backend

    def edit_backend(self, name, serial_number=None, type_device=None,
                     version=None, chip_name=None, url_details=None,
                     name_topology=None, status=None, description=None,
                     gate_set=None, date_online=None,
                     access_token=None, user_id=None):
        """
        Edit a backend by admin
        """
        if access_token:
            self.req.credential.set_token(access_token)
        if user_id:
            self.req.credential.set_user_id(user_id)
        if not self.check_credentials():
            return {"error": "Not credentials valid"}

        data = self.get_backend_by_name(name)

        if not data or ("id" not in data):
            return {"error": "Not backend valid: " + name}

        if name_topology:
            id_topology = self._get_topology_id_from_name(name_topology)

            if not id_topology:
                return {"error": "Not topology valid: " + name_topology}

            data["topologyId"] = id_topology

        if type_device:
            if ((type_device != 'Simulator') and (type_device != 'Real')):
                return {"error": "Not type of the device valid: " +
                        type_device +
                        ". Only allowed 'Simulator' or 'Real'"}
            data["type"] = type_device

        if status:
            if ((status != 'On') and (status != 'Off')):
                return {"error": "Not status of the device valid: " +
                        type_device +
                        ". Only allowed 'On' or 'Off'"}
            data["status"] = status

        if date_online:
            try:
                datetime.strptime(date_online, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                return {"error": "Not date_online valid in ISO Format" +
                        " (YYYY-MM-DDTHH:mm:ss.sssZ): " + date_online}

        if serial_number:
            data["serialNumber"] = serial_number

        if version:
            data["version"] = version
        
        if chip_name:
            data["chipName"] = chip_name

        if url_details:
            data["docUrl"] = url_details

        if date_online:
            data["onlineDate"] = date_online

        if description:
            data["description"] = description
        
        if gate_set:
            data["gateSet"] = gate_set

        backend = self.req.put('/Devices/' + data["id"], data=json.dumps(data))
        return backend


class ApiError(Exception):
    """
    IBMQuantumExperience API error handling base class.
    """
    def __init__(self, usr_msg=None, dev_msg=None):
        """
        Args:
            usr_msg (str): Short user facing message describing error.
            dev_msg (str or None, optional): More detailed message to assist
                developer with resolving issue.
        """
        Exception.__init__(self, usr_msg)
        self.usr_msg = usr_msg
        self.dev_msg = dev_msg

    def __repr__(self):
        return repr(self.dev_msg)

    def __str__(self):
        return str(self.usr_msg)


class BadBackendError(ApiError):
    """
    Unavailable backend error.
    """
    def __init__(self, backend):
        """
        Parameters
        ----------
        backend : str
           Name of backend.
        """
        usr_msg = ('Could not find backend "{0}" available.').format(backend)
        dev_msg = ('Backend "{0}" does not exist. Please use '
                   'available_backends to see options').format(backend)
        ApiError.__init__(self, usr_msg=usr_msg,
                          dev_msg=dev_msg)


class CredentialsError(ApiError):
    """Exception associated with bad server credentials."""
    pass


class RegisterSizeError(ApiError):
    """Exception due to exceeding the maximum number of allowed qubits."""
    pass
