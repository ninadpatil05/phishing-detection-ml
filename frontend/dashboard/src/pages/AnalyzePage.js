import React, { useState, useEffect } from 'react';
import { checkHealth, predictEmail, explainEmail, getFeedbackStats } from '../api';
import './AnalyzePage.css';
import EmailInput from '../components/EmailInput';
import ResultsPanel from '../components/ResultsPanel';
import ExplanationPanel from '../components/ExplanationPanel';
import HistoryTable from '../components/HistoryTable';
import StatsBar from '../components/StatsBar';

function AnalyzePage() {
    const [apiStatus, setApiStatus] = useState('checking');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [explanation, setExplanation] = useState(null);
    const [history, setHistory] = useState([]);
    const [stats, setStats] = useState(null);

    // Check API health on mount
    useEffect(() => {
        checkApiHealth();
        loadStats();
        const interval = setInterval(checkApiHealth, 30000); // Check every 30s
        return () => clearInterval(interval);
    }, []);

    const checkApiHealth = async () => {
        const isHealthy = await checkHealth();
        setApiStatus(isHealthy ? 'online' : 'offline');
    };

    const loadStats = async () => {
        try {
            const statsData = await getFeedbackStats();
            setStats(statsData);
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    };

    const handleAnalyze = async (emailText, withExplanation) => {
        setLoading(true);
        setResult(null);
        setExplanation(null);

        try {
            // Get prediction
            const predResult = await predictEmail(emailText);
            setResult(predResult);

            // Get explanation if requested
            if (withExplanation) {
                const explResult = await explainEmail(emailText);
                setExplanation(explResult);
            }

            // Add to history
            const historyItem = {
                timestamp: new Date().toLocaleString(),
                email_preview: emailText.substring(0, 50) + '...',
                verdict: predResult.verdict,
                risk_score: predResult.risk_score,
            };
            setHistory((prev) => [historyItem, ...prev].slice(0, 10));

            // Reload stats
            loadStats();
        } catch (error) {
            console.error('Analysis failed:', error);
            alert('Analysis failed. Make sure the API is running.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="analyze-page">
            <header className="page-header">
                <h2>Email Analysis</h2>
                <div className="api-status">
                    <span className={`status-indicator ${apiStatus}`}></span>
                    <span>API: {apiStatus}</span>
                </div>
            </header>

            <div className="main-content">
                <div className="left-panel">
                    <EmailInput onAnalyze={handleAnalyze} loading={loading} />
                </div>

                <div className="right-panel">
                    <ResultsPanel result={result} loading={loading} />
                </div>
            </div>

            {explanation && (
                <div className="explanation-section">
                    <ExplanationPanel explanation={explanation} />
                </div>
            )}

            <div className="bottom-section">
                <StatsBar stats={stats} />
                <HistoryTable history={history} />
            </div>
        </div>
    );
}

export default AnalyzePage;
