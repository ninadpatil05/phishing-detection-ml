import React, { useState, useEffect } from 'react';
import { LineChart, Line, PieChart, Pie, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, Cell, ResponsiveContainer } from 'recharts';
import { getFeedbackStats } from '../api';
import './MetricsPage.css';

function MetricsPage() {
    const [stats, setStats] = useState(null);

    useEffect(() => {
        loadStats();
    }, []);

    const loadStats = async () => {
        try {
            const data = await getFeedbackStats();
            setStats(data);
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    };

    // Mock data for charts (in production, this would come from API)
    const predictionsData = Array.from({ length: 30 }, (_, i) => ({
        date: new Date(Date.now() - (29 - i) * 24 * 60 * 60 * 1000).toLocaleDateString(),
        predictions: Math.floor(Math.random() * 50) + 10,
    }));

    const ratioData = stats ? [
        { name: 'Phishing', value: (stats.total_predictions - stats.false_positives) || 25, color: '#ef4444' },
        { name: 'Legitimate', value: stats.false_positives || 75, color: '#22c55e' },
    ] : [];

    const confidenceData = [
        { confidence: 'HIGH', count: 65 },
        { confidence: 'MEDIUM', count: 25 },
        { confidence: 'LOW', count: 10 },
    ];

    return (
        <div className="metrics-page">
            <header className="page-header">
                <h2>Performance Metrics</h2>
            </header>

            <div className="metrics-grid">
                {/* Predictions Over Time */}
                <div className="chart-card full-width">
                    <h3>Predictions Over Last 30 Days</h3>
                    <ResponsiveContainer width="100%" height={300}>
                        <LineChart data={predictionsData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#2a3f5f" />
                            <XAxis dataKey="date" stroke="#94a3b8" />
                            <YAxis stroke="#94a3b8" />
                            <Tooltip
                                contentStyle={{ backgroundColor: '#1a1f3a', border: '1px solid #2a3f5f' }}
                                labelStyle={{ color: '#e0e0e0' }}
                            />
                            <Legend />
                            <Line type="monotone" dataKey="predictions" stroke="#60a5fa" strokeWidth={2} />
                        </LineChart>
                    </ResponsiveContainer>
                </div>

                {/* Phishing vs Safe Ratio */}
                <div className="chart-card">
                    <h3>Phishing vs Legitimate</h3>
                    <ResponsiveContainer width="100%" height={300}>
                        <PieChart>
                            <Pie
                                data={ratioData}
                                cx="50%"
                                cy="50%"
                                labelLine={false}
                                label={(entry) => `${entry.name}: ${entry.value}`}
                                outerRadius={100}
                                fill="#8884d8"
                                dataKey="value"
                            >
                                {ratioData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={entry.color} />
                                ))}
                            </Pie>
                            <Tooltip
                                contentStyle={{ backgroundColor: '#1a1f3a', border: '1px solid #2a3f5f' }}
                            />
                        </PieChart>
                    </ResponsiveContainer>
                </div>

                {/* Confidence Distribution */}
                <div className="chart-card">
                    <h3>Confidence Distribution</h3>
                    <ResponsiveContainer width="100%" height={300}>
                        <BarChart data={confidenceData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#2a3f5f" />
                            <XAxis dataKey="confidence" stroke="#94a3b8" />
                            <YAxis stroke="#94a3b8" />
                            <Tooltip
                                contentStyle={{ backgroundColor: '#1a1f3a', border: '1px solid #2a3f5f' }}
                                labelStyle={{ color: '#e0e0e0' }}
                            />
                            <Bar dataKey="count" fill="#a78bfa" />
                        </BarChart>
                    </ResponsiveContainer>
                </div>

                {/* Feedback Summary */}
                <div className="chart-card full-width">
                    <h3>Recent Feedback Summary</h3>
                    {stats ? (
                        <div className="feedback-summary">
                            <div className="summary-item">
                                <span className="summary-label">Total Predictions:</span>
                                <span className="summary-value">{stats.total_predictions}</span>
                            </div>
                            <div className="summary-item">
                                <span className="summary-label">Feedback Received:</span>
                                <span className="summary-value">{stats.total_feedback}</span>
                            </div>
                            <div className="summary-item">
                                <span className="summary-label">False Positives:</span>
                                <span className="summary-value error">{stats.false_positives}</span>
                            </div>
                            <div className="summary-item">
                                <span className="summary-label">False Negatives:</span>
                                <span className="summary-value error">{stats.false_negatives}</span>
                            </div>
                            <div className="summary-item highlight">
                                <span className="summary-label">Accuracy from Feedback:</span>
                                <span className="summary-value">
                                    {stats.accuracy_from_feedback !== null
                                        ? `${(stats.accuracy_from_feedback * 100).toFixed(1)}%`
                                        : 'N/A'}
                                </span>
                            </div>
                        </div>
                    ) : (
                        <p className="no-data">Loading feedback data...</p>
                    )}
                </div>
            </div>
        </div>
    );
}

export default MetricsPage;
