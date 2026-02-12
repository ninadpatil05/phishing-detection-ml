import React from 'react';
import './ExplanationPanel.css';

function ExplanationPanel({ explanation }) {
    if (!explanation) return null;

    return (
        <div className="explanation-panel">
            <h3>Detailed Explanation</h3>

            <div className="explanation-grid">
                {/* Risk Factors */}
                <div className="factor-section">
                    <h4 className="section-title risk-title">Top Risk Factors</h4>
                    {explanation.top_risk_factors && explanation.top_risk_factors.length > 0 ? (
                        <ul className="factor-list">
                            {explanation.top_risk_factors.map((factor, idx) => (
                                <li key={idx} className="factor-item risk-factor">
                                    <div className="factor-header">
                                        <span className="factor-name">{factor.feature.replace(/_/g, ' ')}</span>
                                        <span className="factor-impact risk-impact">+{(factor.impact * 100).toFixed(1)}%</span>
                                    </div>
                                    <div className="factor-value">{JSON.stringify(factor.value)}</div>
                                </li>
                            ))}
                        </ul>
                    ) : (
                        <p className="no-factors">No risk factors identified</p>
                    )}
                </div>

                {/* Safe Factors */}
                <div className="factor-section">
                    <h4 className="section-title safe-title">Top Safe Factors</h4>
                    {explanation.top_safe_factors && explanation.top_safe_factors.length > 0 ? (
                        <ul className="factor-list">
                            {explanation.top_safe_factors.map((factor, idx) => (
                                <li key={idx} className="factor-item safe-factor">
                                    <div className="factor-header">
                                        <span className="factor-name">{factor.feature.replace(/_/g, ' ')}</span>
                                        <span className="factor-impact safe-impact">{(factor.impact * 100).toFixed(1)}%</span>
                                    </div>
                                    <div className="factor-value">{JSON.stringify(factor.value)}</div>
                                </li>
                            ))}
                        </ul>
                    ) : (
                        <p className="no-factors">No safe factors identified</p>
                    )}
                </div>
            </div>

            {/* Trigger Words */}
            {explanation.trigger_words && explanation.trigger_words.length > 0 && (
                <div className="trigger-words-section">
                    <h4 className="section-title">Trigger Words Detected</h4>
                    <div className="trigger-words">
                        {explanation.trigger_words.map((word, idx) => (
                            <span key={idx} className="trigger-word">{word}</span>
                        ))}
                    </div>
                </div>
            )}

            {/* Human Readable Explanation */}
            <div className="explanation-text">
                <h4 className="section-title">Summary</h4>
                <p>{explanation.explanation_text}</p>
            </div>
        </div>
    );
}

export default ExplanationPanel;
