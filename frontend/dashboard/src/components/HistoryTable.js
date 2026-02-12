import React from 'react';
import './HistoryTable.css';

function HistoryTable({ history }) {
    if (!history || history.length === 0) {
        return (
            <div className="history-table">
                <h3>Recent Analyses</h3>
                <p className="no-history">No analyses yet</p>
            </div>
        );
    }

    return (
        <div className="history-table">
            <h3>Recent Analyses (Last 10)</h3>
            <div className="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Email Preview</th>
                            <th>Verdict</th>
                            <th>Risk Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        {history.map((item, idx) => (
                            <tr key={idx}>
                                <td>{item.timestamp}</td>
                                <td className="preview-cell">{item.email_preview}</td>
                                <td>
                                    <span className={`verdict-tag ${item.verdict === 'PHISHING' ? 'tag-danger' : 'tag-success'}`}>
                                        {item.verdict}
                                    </span>
                                </td>
                                <td className="score-cell">{(item.risk_score * 100).toFixed(1)}%</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

export default HistoryTable;
