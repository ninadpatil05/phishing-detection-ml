import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import './App.css';
import AnalyzePage from './pages/AnalyzePage';
import MetricsPage from './pages/MetricsPage';

function App() {
    return (
        <Router>
            <div className="App">
                <nav className="navbar">
                    <div className="nav-container">
                        <h1 className="nav-title">Phishing Detection ML</h1>
                        <div className="nav-links">
                            <Link to="/" className="nav-link">Analyze</Link>
                            <Link to="/metrics" className="nav-link">Metrics</Link>
                        </div>
                    </div>
                </nav>

                <Routes>
                    <Route path="/" element={<AnalyzePage />} />
                    <Route path="/metrics" element={<MetricsPage />} />
                </Routes>
            </div>
        </Router>
    );
}

export default App;
