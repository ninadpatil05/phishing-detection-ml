import React from 'react';
import './StatsBar.css';

function StatsBar({ stats }) {
    if (!stats) {
        return null;
    }

    const accuracy = stats.accuracy_from_feedback !== null
        ? (stats.accuracy_from_feedback * 100).toFixed(1)
        : 'N/A';

    return (
        <div className="stats-bar">
            <div className="stat-card">
                <div className="stat-value">{stats.total_predictions || 0}</div>
                <div className="stat-label">Total Analyzed</div>
            </div>

            <div className="stat-card">
                <div className="stat-value">{stats.total_feedback || 0}</div>
                <div className="stat-label">Feedback Received</div>
            </div>

            <div className="stat-card">
                <div className="stat-value">{stats.false_positives || 0}</div>
                <div className="stat-label">False Positives</div>
            </div>

            <div className="stat-card">
                <div className="stat-value">{stats.false_negatives || 0}</div>
                <div className="stat-label">False Negatives</div>
            </div>

            <div className="stat-card highlight">
                <div className="stat-value">{accuracy}%</div>
                <div className="stat-label">Feedback Accuracy</div>
            </div>
        </div>
    );
}

export default StatsBar;
