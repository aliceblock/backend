import axios from 'axios'
import cookies from 'js-cookie'
import { baseURL } from '~/config'
import { setAuthToken, resetAuthToken } from '~/utils/auth'

axios.defaults.baseURL = baseURL

const token = cookies.get('x-access-token')
if (token) setAuthToken(token)
else resetAuthToken()
