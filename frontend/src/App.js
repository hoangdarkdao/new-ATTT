import React, { useState } from 'react';
import axios from 'axios';
import './App.css';
import Login from './components/Login';
import Register from './components/Register';
import Blog from './components/Blog';
import Profile from './components/Profile';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

function App() {
  const [currentUser, setCurrentUser] = useState(null);
  const [view, setView] = useState('blog'); // blog, login, register, profile
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const handleLogin = (user) => {
    setCurrentUser(user);
    setIsLoggedIn(true);
    setView('blog');
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setIsLoggedIn(false);
    setView('blog');
  };

  const handleNavigate = (page) => {
    setView(page);
  };

  return (
    <div className="App">
      <nav className="navbar">
        <div className="nav-container">
          <h1 className="logo">📝 Simple Blog</h1>
          <div className="nav-links">
            <button onClick={() => handleNavigate('blog')} className="nav-btn">Home</button>
            {isLoggedIn ? (
              <>
                <button onClick={() => handleNavigate('profile')} className="nav-btn">
                  Profile ({currentUser?.username})
                </button>
                <button onClick={handleLogout} className="nav-btn logout-btn">Logout</button>
              </>
            ) : (
              <>
                <button onClick={() => handleNavigate('login')} className="nav-btn">Login</button>
                <button onClick={() => handleNavigate('register')} className="nav-btn">Register</button>
              </>
            )}
          </div>
        </div>
      </nav>

      <div className="container">
        {view === 'blog' && <Blog currentUser={currentUser} isLoggedIn={isLoggedIn} />}
        {view === 'login' && <Login onLogin={handleLogin} onSwitchToRegister={() => handleNavigate('register')} />}
        {view === 'register' && <Register onSwitchToLogin={() => handleNavigate('login')} />}
        {view === 'profile' && isLoggedIn && <Profile user={currentUser} />}
      </div>
    </div>
  );
}

export default App;
