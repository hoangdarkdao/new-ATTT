import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

// Create axios instance
const apiClient = axios.create({
  baseURL: API_URL,
  withCredentials: true, // Include cookies in requests
});

let csrfToken = null;

// Fetch CSRF token from backend
const fetchCSRFToken = async () => {
  try {
    if (!csrfToken) {
      const response = await apiClient.get(`${API_URL}/csrf-token`);
      csrfToken = response.data.csrf_token;
    }
    console.log('Fetched CSRF token:', csrfToken);
    return csrfToken;
  } catch (error) {
    console.error('Failed to fetch CSRF token:', error);
    return null;
  }
};

// Request interceptor - add CSRF token to POST/PUT/DELETE requests
apiClient.interceptors.request.use(
  async (config) => {
    // Only add CSRF token for state-changing requests
    if (['post', 'put', 'delete', 'patch'].includes(config.method)) {
      const token = await fetchCSRFToken();
      if (token) {
        config.headers['X-CSRFToken'] = token;
      }
      const auth_token = localStorage.getItem('auth_token');
      if (auth_token) {
        config.headers['Authorization'] = `Bearer ${auth_token}`;
      }
    }
    console.log("interceptor");
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor - handle errors
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 403) {
      // CSRF token invalid - fetch new one
      csrfToken = null;
    }
    return Promise.reject(error);
  }
);

export default apiClient;
