"""
Database Models and Session Management

This module provides SQLAlchemy ORM models for the phishing detection API.
It replaces the previous raw sqlite3 implementation with proper ORM support.

Why SQLAlchemy ORM?
-------------------
- **Type Safety**: Python objects instead of raw SQL strings
- **Relationships**: Automatic handling of foreign keys
- **Migrations**: Easy schema changes with Alembic
- **Query Building**: Pythonic API instead of string manipulation
- **Connection Pooling**: Better performance and resource management
- **Portability**: Easy to switch from SQLite to PostgreSQL/MySQL

Database Schema:
----------------
1. **Predictions Table**:
   - Stores all phishing detection predictions
   - Primary key: id (auto-increment)
   - Unique: prediction_id (UUID)
   - Links to feedback via one-to-many relationship

2. **Feedback Table**:
   - Stores user corrections and feedback
   - Primary key: id (auto-increment)
   - Foreign key: prediction_id → predictions table
   - Tracks if feedback was used in model retraining
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.sql import func
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List
import logging

logger = logging.getLogger(__name__)

# Database path
DB_PATH = Path("data/api_predictions.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# SQLAlchemy setup
DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Needed for SQLite
    echo=False  # Set to True for SQL query logging
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all models
Base = declarative_base()


# ============================================================================
# ORM MODELS
# ============================================================================

class Prediction(Base):
    """
    Prediction model - stores all phishing detection predictions.
    
    Relationships:
    - One prediction can have many feedback entries (one-to-many)
    
    Why we track all these fields:
    - email_text: For retraining with actual examples
    - risk_score, verdict, confidence: For accuracy tracking
    - text_score, url_score: For debugging individual classifiers
    - timestamp: For temporal analysis (model drift over time)
    """
    __tablename__ = "predictions"
    
    # Primary key (auto-increment)
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Unique prediction identifier (UUID format)
    prediction_id = Column(String, unique=True, index=True, nullable=False)
    
    # Email content (truncated for storage)
    email_text = Column(Text, nullable=False)
    
    # Prediction scores
    risk_score = Column(Float, nullable=False)  # Ensemble score (0-1)
    text_score = Column(Float, nullable=False)  # Text classifier score
    url_score = Column(Float, nullable=False)   # URL classifier score
    
    # Classification results
    verdict = Column(String, nullable=False)  # PHISHING or SAFE
    confidence = Column(String, nullable=True)  # HIGH, MEDIUM, LOW (added later)
    
    # Metadata
    model_version = Column(String, nullable=True)  # e.g., "1.0.0"
    processing_time_ms = Column(Float, nullable=True)  # Performance tracking
    
    # Timestamps
    timestamp = Column(DateTime, nullable=False)  # When prediction was made
    created_at = Column(DateTime, server_default=func.now())  # DB insertion time
    
    # Relationships
    feedback_entries = relationship("Feedback", back_populates="prediction", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Prediction(id={self.id}, prediction_id='{self.prediction_id}', verdict='{self.verdict}')>"


class Feedback(Base):
    """
    Feedback model - stores user corrections on predictions.
    
    Relationships:
    - Many feedback entries belong to one prediction (many-to-one)
    
    Purpose:
    - Track model errors (false positives/negatives)
    - Collect data for model retraining
    - Measure real-world accuracy
    - Enable continuous learning
     
    The `used_in_training` field:
    - Initially False when feedback is submitted
    - Set to True after feedback is incorporated into retraining dataset
    - Prevents duplicate use of same feedback in multiple training runs
    """
    __tablename__ = "feedback"
    
    # Primary key (auto-increment)
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Unique feedback identifier (UUID format)
    feedback_id = Column(String, unique=True, index=True, nullable=False)
    
    # Foreign key to predictions table
    prediction_id = Column(String, ForeignKey("predictions.prediction_id"), nullable=False, index=True)
    
    # True label (user correction)
    # 0 = SAFE/LEGITIMATE, 1 = PHISHING
    true_label = Column(Integer, nullable=False)  # 0 or 1
    
    # Optional comment/context from user
    comment = Column(Text, nullable=True)
    
    # Tracking for model retraining
    used_in_training = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    submitted_at = Column(DateTime, server_default=func.now())  # When feedback was submitted
    
    # Relationships
    prediction = relationship("Prediction", back_populates="feedback_entries")
    
    def __repr__(self):
        return f"<Feedback(id={self.id}, prediction_id='{self.prediction_id}', true_label={self.true_label})>"


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)
    logger.info(f"Database initialized at {DB_PATH}")


# Initialize database on module import
init_db()


# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

def get_db() -> Session:
    """
    Get database session (dependency injection for FastAPI).
    
    Usage in FastAPI:
    -----------------
    @app.get("/endpoint")
    def my_endpoint(db: Session = Depends(get_db)):
        # Use db session here
        prediction = db.query(Prediction).first()
        return prediction
    
    The session is automatically closed after the request completes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

class DatabaseHelper:
    """Helper class for common database operations."""
    
    @staticmethod
    def save_prediction(db: Session, prediction_data: Dict) -> bool:
        """
        Save prediction to database.
        
        Parameters:
        -----------
        db : Session
            SQLAlchemy session
        prediction_data : dict
            Prediction data to save
            
        Returns:
        --------
        success : bool
            Whether save was successful
        """
        try:
            prediction = Prediction(
                prediction_id=prediction_data['prediction_id'],
                email_text=prediction_data['email_text'],
                risk_score=prediction_data['risk_score'],
                verdict=prediction_data['verdict'],
                confidence=prediction_data.get('confidence'),
                text_score=prediction_data['text_score'],
                url_score=prediction_data['url_score'],
                processing_time_ms=prediction_data.get('processing_time_ms'),
                model_version=prediction_data.get('model_version', '1.0.0'),
                timestamp=datetime.fromisoformat(prediction_data['timestamp']) if isinstance(prediction_data['timestamp'], str) else prediction_data['timestamp']
            )
            
            db.add(prediction)
            db.commit()
            db.refresh(prediction)
            
            logger.info(f"Saved prediction: {prediction.prediction_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save prediction: {str(e)}")
            db.rollback()
            return False
    
    @staticmethod
    def get_prediction(db: Session, prediction_id: str) -> Optional[Prediction]:
        """
        Retrieve prediction by ID.
        
        Parameters:
        -----------
        db : Session
            SQLAlchemy session
        prediction_id : str
            Prediction ID to retrieve
            
        Returns:
        --------
        prediction : Prediction or None
            Prediction object or None if not found
        """
        try:
            return db.query(Prediction).filter(Prediction.prediction_id == prediction_id).first()
        except Exception as e:
            logger.error(f"Failed to retrieve prediction: {str(e)}")
            return None
    
    @staticmethod
    def save_feedback(db: Session, feedback_data: Dict) -> bool:
        """
        Save feedback to database.
        
        Parameters:
        -----------
        db : Session
            SQLAlchemy session
        feedback_data : dict
            Feedback data to save
            
        Returns:
        --------
        success : bool
            Whether save was successful
        """
        try:
            feedback = Feedback(
                feedback_id=feedback_data['feedback_id'],
                prediction_id=feedback_data['prediction_id'],
                true_label=feedback_data['true_label'],
                comment=feedback_data.get('comment'),
                used_in_training=False  # Initially not used
            )
            
            db.add(feedback)
            db.commit()
            db.refresh(feedback)
            
            logger.info(f"Saved feedback: {feedback.feedback_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save feedback: {str(e)}")
            db.rollback()
            return False
    
    @staticmethod
    def get_feedback_stats(db: Session) -> Dict:
        """
        Calculate feedback statistics.
        
        Returns:
        --------
        stats : dict
            Dictionary containing:
            - total_predictions: Total number of predictions
            - total_feedback: Total feedback submitted
            - false_positives: Predicted phishing, actually safe
            - false_negatives: Predicted safe, actually phishing
            - accuracy_from_feedback: Accuracy based on feedback data
        """
        try:
            # Total predictions
            total_predictions = db.query(Prediction).count()
            
            # Total feedback
            total_feedback = db.query(Feedback).count()
            
            # Join predictions with feedback to calculate errors
            # False Positives: model predicted PHISHING (verdict='PHISHING'), but user said SAFE (true_label=0)
            false_positives = db.query(Feedback).join(
                Prediction, Prediction.prediction_id == Feedback.prediction_id
            ).filter(
                Prediction.verdict == "PHISHING",
                Feedback.true_label == 0
            ).count()
            
            # False Negatives: model predicted SAFE (verdict='SAFE'), but user said PHISHING (true_label=1)
            false_negatives = db.query(Feedback).join(
                Prediction, Prediction.prediction_id == Feedback.prediction_id
            ).filter(
                Prediction.verdict == "SAFE",
                Feedback.true_label == 1
            ).count()
            
            # Calculate accuracy from feedback
            if total_feedback > 0:
                # Correct predictions = total feedback - (false positives + false negatives)
                correct_predictions = total_feedback - (false_positives + false_negatives)
                accuracy_from_feedback = correct_predictions / total_feedback
            else:
                accuracy_from_feedback = None  # No feedback yet
            
            return {
                'total_predictions': total_predictions,
                'total_feedback': total_feedback,
                'false_positives': false_positives,
                'false_negatives': false_negatives,
                'accuracy_from_feedback': accuracy_from_feedback
            }
            
        except Exception as e:
            logger.error(f"Failed to calculate stats: {str(e)}")
            return {
                'total_predictions': 0,
                'total_feedback': 0,
                'false_positives': 0,
                'false_negatives': 0,
                'accuracy_from_feedback': None,
                'error': str(e)
            }


# ============================================================================
# BACKWARDS COMPATIBILITY
# ============================================================================

class Database:
    """
    Legacy Database class for backwards compatibility.
    
    This wraps the new SQLAlchemy implementation to maintain
    compatibility with existing code that uses the old interface.
    """
    
    def __init__(self, db_path: str = None):
        """Initialize database (already initialized by init_db())."""
        logger.info(f"Using SQLAlchemy ORM with database at {DB_PATH}")
    
    def save_prediction(self, prediction_data: Dict) -> bool:
        """Save prediction (legacy interface)."""
        db = SessionLocal()
        try:
            return DatabaseHelper.save_prediction(db, prediction_data)
        finally:
            db.close()
    
    def get_prediction(self, prediction_id: str) -> Optional[Dict]:
        """Get prediction (legacy interface) - returns dict for compatibility."""
        db = SessionLocal()
        try:
            pred = DatabaseHelper.get_prediction(db, prediction_id)
            if pred:
                return {
                    'prediction_id': pred.prediction_id,
                    'email_text': pred.email_text,
                    'risk_score': pred.risk_score,
                    'verdict': pred.verdict,
                    'confidence': pred.confidence,
                    'text_score': pred.text_score,
                    'url_score': pred.url_score,
                    'timestamp': pred.timestamp.isoformat() if pred.timestamp else None
                }
            return None
        finally:
            db.close()
    
    def save_feedback(self, feedback_data: Dict) -> bool:
        """Save feedback (legacy interface)."""
        db = SessionLocal()
        try:
            return DatabaseHelper.save_feedback(db, feedback_data)
        finally:
            db.close()


# Global database instance for backwards compatibility
db = Database()
