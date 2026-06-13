import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

function Profile({ user }) {
  const [profile, setProfile] = useState(null);
  const [bio, setBio] = useState('');
  const [isEditing, setIsEditing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    fetchProfile();
  }, []);

  const fetchProfile = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${API_URL}/users/${user.user_id}`);
      setProfile(response.data);
      setBio(response.data.bio || '');
    } catch (err) {
      setError('Failed to load profile');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      await axios.post(`${API_URL}/users/${user.user_id}/update`, {
        bio
      });
      setSuccess('Profile updated successfully!');
      setIsEditing(false);
      fetchProfile();
    } catch (err) {
      setError('Failed to update profile');
    }
  };

  if (loading) return <div>Loading profile...</div>;
  if (!profile) return <div>Profile not found</div>;

  return (
    <div style={{ maxWidth: '600px', margin: '0 auto' }}>
      <div style={{ background: 'white', padding: '2rem', borderRadius: '8px', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>
        <h2>👤 User Profile</h2>
        
        {error && <div className="error">{error}</div>}
        {success && <div className="success">{success}</div>}

        <div style={{ marginBottom: '2rem', borderBottom: '1px solid #eee', paddingBottom: '1rem' }}>
          <p><strong>Username:</strong> {profile.username}</p>
          <p><strong>Email:</strong> {profile.email}</p>
          <p><strong>Member Since:</strong> {new Date(profile.created_at).toLocaleDateString()}</p>
        </div>

        {isEditing ? (
          <form onSubmit={handleUpdateProfile}>
            <div className="form-group">
              <label htmlFor="bio">Bio</label>
              <textarea
                id="bio"
                value={bio}
                onChange={(e) => setBio(e.target.value)}
                placeholder="Tell us about yourself..."
                rows="5"
              />
            </div>

            <div style={{ display: 'flex', gap: '1rem' }}>
              <button type="submit" className="btn" style={{ flex: 1 }}>Save Changes</button>
              <button 
                type="button" 
                onClick={() => setIsEditing(false)} 
                className="btn btn-secondary"
                style={{ flex: 1, backgroundColor: '#95a5a6' }}
              >
                Cancel
              </button>
            </div>
          </form>
        ) : (
          <div>
            <div style={{ marginBottom: '1rem', padding: '1rem', background: '#f8f9fa', borderRadius: '4px' }}>
              <h4>Bio</h4>
              <p>{bio || '<No bio added yet>'}</p>
            </div>

            <button 
              onClick={() => setIsEditing(true)}
              className="btn"
            >
              Edit Profile
            </button>
          </div>
        )}

        <div style={{ marginTop: '2rem', padding: '1rem', background: '#e8f4f8', borderRadius: '4px', fontSize: '0.9rem' }}>
          <strong>Note:</strong> Your profile information is publicly visible on the blog.
        </div>
      </div>
    </div>
  );
}

export default Profile;
