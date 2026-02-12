# Phishing Detection Dashboard

A professional React dashboard for analyzing emails and detecting phishing attempts using machine learning.

## Features

### Main Analysis Page
- **Email Input**: Large textarea for pasting email content
- **Real-time Analysis**: Get instant predictions with risk scores
- **Risk Gauge**: Visual gauge showing phishing probability (0-100%)
- **Detailed Results**: Verdict, confidence level, and individual model scores
- **Explanation Mode**: Toggle to get detailed explanations with:
  - Top risk factors with impact scores
  - Top safe factors
  - Trigger words highlighted
  - Human-readable summary
- **History Table**: Last 10 analyses
- **Stats Bar**: Total analyzed, feedback accuracy, error rates

### Metrics Page
- **Predictions Chart**: Line chart showing predictions over last 30 days
- **Phishing Ratio**: Pie chart of phishing vs legitimate emails
- **Confidence Distribution**: Bar chart of HIGH/MEDIUM/LOW confidence counts
- **Feedback Summary**: Real-time statistics from user feedback

## Tech Stack

- **React 18**: UI framework
- **React Router**: Client-side routing
- **Axios**: API communication
- **Recharts**: Data visualization
- **Dark Theme**: Professional styling optimized for long sessions

## Setup Instructions

### Prerequisites

- Node.js 16+ and npm
- Phishing Detection API running on `http://localhost:8000`

### Installation

1. Navigate to dashboard directory:
```bash
cd frontend/dashboard
```

2. Install dependencies:
```bash
npm install
```

3. Configure API URL (optional):
Edit `.env` file to change API base URL:
```
REACT_APP_API_BASE_URL=http://localhost:8000/api/v1
```

4. Start development server:
```bash
npm start
```

The dashboard will open at `http://localhost:3000`

### Building for Production

```bash
npm run build
```

Build output will be in the `build/` directory.

## API Endpoints Used

- `POST /api/v1/predict`: Get phishing prediction
- `POST /api/v1/explain`: Get detailed explanation
- `GET /api/v1/feedback/stats`: Get feedback statistics
- `GET /health`: API health check

## Usage

### Analyzing an Email

1. Paste email content into the textarea
2. (Optional) Check "Include Explanation" for detailed analysis
3. Click "Analyze Email"
4. View results in the right panel
5. If explanation enabled, scroll down to see risk factors

### Sample Email

Click "Load Sample" to load a phishing email example for testing.

### Viewing Metrics

Click "Metrics" in the navigation to see:
- Historical prediction trends
- Classification distribution
- Feedback accuracy
- Error analysis

## Project Structure

```
frontend/dashboard/
├── public/
│   └── index.html          # HTML template
├── src/
│   ├── api.js              # API service layer
│   ├── App.js              # Main app with routing
│   ├── App.css             # App styles
│   ├── index.js            # React entry point
│   ├── index.css           # Global styles
│   ├── components/         # Reusable components
│   │   ├── EmailInput.js
│   │   ├── ResultsPanel.js
│   │   ├── ExplanationPanel.js
│   │   ├── HistoryTable.js
│   │   └── StatsBar.js
│   └── pages/              # Page components
│       ├── AnalyzePage.js
│       └── MetricsPage.js
├── package.json
└── .env                    # Environment variables
```

## Design Choices

### Dark Theme
Professional dark color scheme reduces eye strain during extended use and creates a modern, tech-focused aesthetic.

### Real-time API Status
Header shows live API connection status with color-coded indicator:
- 🟢 Green: API online
- 🔴 Red: API offline
- 🟡 Yellow: Checking

### Risk Gauge Visualization
SVG-based gauge provides intuitive visual feedback on phishing probability with color coding:
- Red: High risk (>70%)
- Orange: Medium risk (40-70%)
- Green: Low risk (<40%)

### Responsive Layout
Grid-based layout adapts to different screen sizes, maintaining usability on tablets and mobile devices.

## Troubleshooting

### Dashboard won't load
- Ensure Node.js and npm are installed
- Run `npm install` to install dependencies
- Check for port conflicts (default: 3000)

### API connection fails
- Verify API is running at configured URL
- Check `.env` file for correct `REACT_APP_API_BASE_URL`
- Ensure CORS is enabled on API server

### Charts not displaying
- Check browser console for errors
- Ensure Recharts is installed: `npm list recharts`
- Refresh the page

## Future Enhancements

- User authentication and sessions
- Feedback submission interface
- Export reports to PDF
- Email batch upload
- Custom model selection
- Real-time notifications

## License

MIT
