import React, { useState } from "react";
import "./LoginPage.css";

const LoginPage = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleLogin = (e) => {
    e.preventDefault();
    // Replace this logic with your real authentication API call
    if (username === "admin" && password === "password") {
      setError("");
      alert("Login successful!");
      // Redirect to dashboard or home page
    } else {
      setError("Invalid username or password.");
    }
  };

  return (
    <div className="login-container">
      <form className="login-form" onSubmit={handleLogin}>
        <h2>Login</h2>
        {error && <div className="error">{error}</div>}
        <label>
          Username
          <input
            type="text"
            value={username}
            onChange={e => setUsername(e.target.value)}
            required
            autoFocus
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
          />
        </label>
        <button type="submit">Login</button>
      </form>
    </div>
  );
};




CSS::
.login-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f7f8fa;
}

.login-form {
  background: #fff;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 2px 12px rgba(0,0,0,0.09);
  width: 100%;
  max-width: 350px;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.login-form h2 {
  margin-bottom: 1rem;
  text-align: center;
}

.login-form label {
  display: flex;
  flex-direction: column;
  font-size: 1rem;
}

.login-form input {
  margin-top: 0.5rem;
  padding: 0.6rem;
  font-size: 1rem;
  border: 1px solid #e0e3eb;
  border-radius: 4px;
}

.login-form .error {
  color: #e74c3c;
  background: #ffeaea;
  padding: 0.5rem;
  border-radius: 4px;
  font-size: 0.95rem;
  text-align: center;
}

.login-form button {
  padding: 0.7rem;
  background: #2d72d9;
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
  margin-top: 0.5rem;
  transition: background 0.2s;
}

.login-form button:hover {
  background: #245bb5;
}

@media (max-width: 500px) {
  .login-form {
    padding: 1rem;
    max-width: 95vw;
  }
}
