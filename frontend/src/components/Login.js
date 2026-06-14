import React, { useState } from 'react';
import apiClient from '../services/apiClient';

function Login({ onLogin, onSwitchToRegister }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await apiClient.post('/login', {
        username,
        password
      });

      if (response.data.success) {
        const token = response.data.token;
        localStorage.setItem('auth_token', token);
        onLogin(response.data);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed');
      console.log('Login error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="form-container">
      <h2>Login</h2>
      {error && <div className="error">{error}</div>}
      
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter your username"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
            required
          />
        </div>

        <button type="submit" className="btn" disabled={loading}>
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </form>

      <div className="switch-auth">
        Don't have an account? <a onClick={onSwitchToRegister}>Register here</a>
      </div>

      <div style={{ marginTop: '2rem', padding: '1rem', background: '#fff3cd', borderRadius: '4px', fontSize: '0.9rem' }}>
        <strong>Demo Credentials:</strong><br />
        Username: admin<br />
        Password: admin123<br />
        <br />
        <strong>Note:</strong> This login system is intentionally vulnerable for testing purposes.
      </div>
    </div>
  );
}

export default Login;
