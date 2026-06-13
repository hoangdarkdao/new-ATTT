import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

function Blog({ currentUser, isLoggedIn }) {
  const [posts, setPosts] = useState([]);
  const [searchResults, setSearchResults] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [newPost, setNewPost] = useState({ title: '', content: '' });
  const [newComments, setNewComments] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchPosts();
  }, []);

  const fetchPosts = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${API_URL}/posts`);
      setPosts(response.data.posts);
    } catch (err) {
      setError('Failed to load posts');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      setSearchResults([]);
      return;
    }

    try {
      const response = await axios.get(`${API_URL}/search`, {
        params: { q: searchQuery }
      });
      setSearchResults(response.data.results);
    } catch (err) {
      setError('Search failed');
    }
  };

  const handleCreatePost = async (e) => {
    e.preventDefault();
    if (!isLoggedIn) {
      setError('Please login to create a post');
      return;
    }

    try {
      await axios.post(`${API_URL}/posts`, {
        ...newPost,
        user_id: currentUser.user_id
      });
      setNewPost({ title: '', content: '' });
      fetchPosts();
    } catch (err) {
      setError('Failed to create post');
    }
  };

  const handleAddComment = async (postId) => {
    if (!isLoggedIn) {
      setError('Please login to add a comment');
      return;
    }

    const content = newComments[postId];
    if (!content?.trim()) return;

    try {
      await axios.post(`${API_URL}/comments`, {
        content,
        post_id: postId,
        user_id: currentUser.user_id
      });
      setNewComments({ ...newComments, [postId]: '' });
      fetchPosts();
    } catch (err) {
      setError('Failed to add comment');
    }
  };

  if (loading) return <div>Loading posts...</div>;

  return (
    <div>
      <h2>📰 Blog Posts</h2>
      {error && <div className="error">{error}</div>}

      {/* Search Section */}
      <div className="search-container">
        <h3>Search Users</h3>
        <div className="search-box">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search for users..."
          />
          <button onClick={handleSearch}>Search</button>
        </div>
        
        {searchResults.length > 0 && (
          <div className="search-results">
            <h4>Results ({searchResults.length}):</h4>
            {searchResults.map((user) => (
              <div key={user.id} className="search-result-item">
                <strong>@{user.username}</strong> (ID: {user.id})
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Create Post Section */}
      {isLoggedIn && (
        <div style={{ background: 'white', padding: '1.5rem', marginBottom: '2rem', borderRadius: '8px', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>
          <h3>Create New Post</h3>
          <form onSubmit={handleCreatePost}>
            <div className="form-group">
              <label>Title</label>
              <input
                type="text"
                value={newPost.title}
                onChange={(e) => setNewPost({ ...newPost, title: e.target.value })}
                placeholder="Post title..."
                required
              />
            </div>

            <div className="form-group">
              <label>Content</label>
              <textarea
                value={newPost.content}
                onChange={(e) => setNewPost({ ...newPost, content: e.target.value })}
                placeholder="Write your post content..."
                rows="5"
                required
              />
            </div>

            <button type="submit" className="btn">Publish Post</button>
          </form>
        </div>
      )}

      {/* Posts Section */}
      <div>
        {posts.length === 0 ? (
          <p>No posts yet. Be the first to post!</p>
        ) : (
          posts.map((post) => (
            <div key={post.id} className="post">
              <div className="post-header">
                <div>
                  <h3 className="post-title">{post.title}</h3>
                  <div className="post-meta">
                    By <strong>@{post.username}</strong> on {new Date(post.created_at).toLocaleDateString()}
                  </div>
                </div>
              </div>

              <div className="post-content">{post.content}</div>

              <div className="comments-section">
                <h4>Comments ({post.comments.length})</h4>
                
                {post.comments.length > 0 && (
                  <div>
                    {post.comments.map((comment) => (
                      <div key={comment.id} className="comment">
                        <div className="comment-author">@{comment.username}</div>
                        <div className="comment-date">
                          {new Date(comment.created_at).toLocaleDateString()}
                        </div>
                        <div className="comment-content">{comment.content}</div>
                      </div>
                    ))}
                  </div>
                )}

                {isLoggedIn && (
                  <div style={{ marginTop: '1rem', display: 'flex', gap: '0.5rem' }}>
                    <textarea
                      value={newComments[post.id] || ''}
                      onChange={(e) => setNewComments({ ...newComments, [post.id]: e.target.value })}
                      placeholder="Add a comment..."
                      rows="2"
                      style={{ flex: 1 , width: '100%'}}
                    />
                    <button 
                      onClick={() => handleAddComment(post.id)}
                      style={{ padding: '0.75rem 1.5rem', width:'auto', height: 'fit-content' }}
                      className="btn"
                    >
                      Post
                    </button>
                  </div>
                )}

                {!isLoggedIn && (
                  <p style={{ color: '#7f8c8d', marginTop: '1rem' }}>
                    <em>Please login to add a comment</em>
                  </p>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default Blog;
