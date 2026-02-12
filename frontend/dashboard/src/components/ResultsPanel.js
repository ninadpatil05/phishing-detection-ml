import React from 'react';
import './ResultsPanel.css';

function ResultsPanel({ result, loading }) {
    if (loading) {
        return (
            <div className="results-panel">
                <div className="loading">Analyzing email...</div>
            </div>
        );
    }

    if (!result) {
        return (
            <div className="results-panel">
                <div className="placeholder">
                    <p>Results will appear here after analysis</p>
                </div>
            </div>
        );
    }

    const getRiskColor = (score) => {
        if (score >= 0.7) return '#ef4444';
        if (score >= 0.4) return '#f59e0b';
        return '#22c55e';
    };

    const getVerdictClass = (verdict) => {
        return verdict === 'PHISHING' ? 'verdict-phishing' : 'verdict-safe';
    };

    const getConfidenceClass = (confidence) => {
        const classes = {
            HIGH: 'confidence-high',
            MEDIUM: 'confidence-medium',
            LOW: 'confidence-low',
        };
        return classes[confidence] || 'confidence-medium';
    };

    return (
        <div className="results-panel">
            <h3>Analysis Results</h3>

            {/* Risk Score Gauge */}
            <div className="gauge-container">
                <div className="gauge">
                    <svg width="200" height="120" viewBox="0 0 200 120">
                        {/* Background arc */}
                        <path
                            d="M 20 100 A 80 80 0 0 1 180 100"
                            fill="none"
                            stroke="#2a3f5f"
                            strokeWidth="20"
                        />
                        {/* Progress arc */}
                        <path
                            d={`M 20 100 A 80 80 0 ${result.risk_score > 0.5 ? 1 : 0} 1 ${20 + 160 * result.risk_score
                                } ${100 - 80 * Math.sin((Math.PI * result.risk_score))}`}
                            fill="none"
                            stroke={getRiskColor(result.risk_score)}
                            strokeWidth="20"
                            strokeLinecap="round"
                        />
                    </svg>
                    <div className="gauge-value" style={{ color: getRiskColor(result.risk_score) }}>
                        {(result.risk_score * 100).toFixed(1)}%
                    </div>
                    <div className="gauge-label">Risk Score</div>
                </div>
            </div>

            {/* Verdict Badge */}
            <div className={`verdict-badge ${getVerdictClass(result.verdict)}`}>
                {result.verdict}
            </div>

            {/* Confidence Level */}
            <div className={`confidence-badge ${getConfidenceClass(result.confidence)}`}>
                Confidence: {result.confidence}
            </div>

            {/* Individual Scores */}
            <div className="scores-grid">
                <div className="score-item">
                    <div className="score-label">Text Score</div>
                    <div className="score-value">{(result.text_score * 100).toFixed(1)}%</div>
                </div>
                <div className="score-item">
                    <div className="score-label">URL Score</div>
                    <div className="score-value">{(result.url_score * 100).toFixed(1)}%</div>
                </div>
                <div className="score-item">
                    <div className="score-label">Ensemble Score</div>
                    <div className="score-value">{(result.ensemble_score * 100).toFixed(1)}%</div>
                </div>
            </div>

            {/* Processing Time */}
            <div className="meta-info">
                <span>Processed in {result.processing_time_ms?.toFixed(2) || 0} ms</span>
                <span>Model v{result.model_version || '1.0.0'}</span>
            </div>
        </div>
    );
}

export default ResultsPanel;
