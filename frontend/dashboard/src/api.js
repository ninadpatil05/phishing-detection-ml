import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000/api/v1';

const api = axios.create({
    baseURL: API_BASE_URL,
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Prediction API
export const predictEmail = async (emailText) => {
    const response = await api.post('/predict', { email_text: emailText });
    return response.data;
};

// Explanation API
export const explainEmail = async (emailText) => {
    const response = await api.post('/explain', { email_text: emailText });
    return response.data;
};

// Feedback API
export const submitFeedback = async (predictionId, trueLabel, comment = '') => {
    const response = await api.post('/feedback', {
        prediction_id: predictionId,
        true_label: trueLabel,
        comment,
    });
    return response.data;
};

// Feedback Stats API
export const getFeedbackStats = async () => {
    const response = await api.get('/feedback/stats');
    return response.data;
};

// Health Check
export const checkHealth = async () => {
    try {
        const response = await axios.get(`${API_BASE_URL.replace('/api/v1', '')}/health`, { timeout: 5000 });
        return response.status === 200;
    } catch (error) {
        return false;
    }
};

export default api;
