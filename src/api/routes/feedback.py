"""
Feedback Routes for Phishing Detection API

This module provides feedback endpoints for users to correct model predictions.
Feedback is used for continuous model improvement through retraining.

How Feedback Improves the Model:
---------------------------------
1. **Collection**: Users submit corrections on predictions
2. **Storage**: Feedback stored in database with true labels
3. **Aggregation**: Periodically batch all new feedback
4. **Retraining**: Add feedback to training dataset and retrain model
5. **Deployment**: Deploy improved model to production
6. **Iteration**: Repeat cycle for continuous improvement

This creates a "feedback loop" where:
- Model makes predictions
- Users correct errors
- Model learns from mistakes
- Accuracy improves over time

The `used_in_training` field prevents duplicate use of same feedback.
"""

from fastapi import APIRouter, HTTPException, status, Request, Depends
from slowapi import Limiter
from slowapi.util import get_remote_address
import uuid
from datetime import datetime
import logging
from sqlalchemy.orm import Session

from api.models import (
    FeedbackRequest, FeedbackResponse,
    FeedbackStatsResponse
)
from api.database import get_db, Prediction, Feedback, DatabaseHelper

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1", tags=["Feedback"])

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@router.post("/feedback", response_model=FeedbackResponse)
@limiter.limit("100/minute")
async def submit_feedback(
    request: Request,
    data: FeedbackRequest,
    db: Session = Depends(get_db)
):
    """
    Submit feedback on a prediction to help improve the model.
    
    **Purpose:**
    - Collect user corrections on model predictions
    - Track false positives and false negatives
    - Build dataset for model retraining
    - Enable continuous learning
    
    **Process:**
    1. Validate that prediction_id exists in database
    2. Create unique feedback_id
    3. Store feedback with true_label (0=SAFE, 1=PHISHING)
    4. Mark as `used_in_training=False` (not yet used in retraining)
    5. Return confirmation with feedback_id
    
    **How This Improves the Model:**
    - Feedback is collected over time
    - Periodically, all unused feedback (`used_in_training=False`) is extracted
    - This data is added to the training dataset
    - Model is retrained with the expanded dataset
    - After retraining, feedback is marked `used_in_training=True`
    - New model is deployed, completing the feedback loop
    
    **Input:**
    - prediction_id: UUID of the prediction to provide feedback on
    - true_label: Correct label (0 = SAFE, 1 = PHISHING)
    - comment: Optional context or explanation
    
    **Output:**
    - message: Confirmation message
    - feedback_id: Unique ID for this feedback
    - will_improve_model: Always True (all feedback helps!)
    
    **Rate Limit:** 100 requests/minute per IP
    
    **Example Request:**
    ```json
    {
        "prediction_id": "pred_20260211_abc123",
        "true_label": 0,
        "comment": "This was a legitimate marketing email"
    }
    ```
    
    **Example Response:**
    ```json
    {
        "message": "Thank you for feedback. Your input helps improve our model!",
        "feedback_id": "fb_20260211_xyz789",
        "will_improve_model": true
    }
    ```
    """
    try:
        # 1. Validate prediction_id exists
        prediction = DatabaseHelper.get_prediction(db, data.prediction_id)
        
        if not prediction:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Prediction ID '{data.prediction_id}' not found. Cannot submit feedback for non-existent prediction."
            )
        
        # 2. Check if feedback already exists for this prediction
        existing_feedback = db.query(Feedback).filter(
            Feedback.prediction_id == data.prediction_id
        ).first()
        
        if existing_feedback:
            # Update existing feedback instead of creating duplicate
            existing_feedback.true_label = data.true_label
            existing_feedback.comment = data.comment
            existing_feedback.submitted_at = datetime.now()
            db.commit()
            
            logger.info(f"Updated existing feedback for prediction: {data.prediction_id}")
            
            return FeedbackResponse(
                message="Thank you for feedback. We've updated your previous submission!",
                feedback_id=existing_feedback.feedback_id,
                will_improve_model=True
            )
        
        # 3. Generate unique feedback ID
        feedback_id = f"fb_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # 4. Save feedback to database
        feedback_data = {
            'feedback_id': feedback_id,
            'prediction_id': data.prediction_id,
            'true_label': data.true_label,
            'comment': data.comment
        }
        
        success = DatabaseHelper.save_feedback(db, feedback_data)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save feedback to database"
            )
        
        # 5. Log feedback for monitoring
        # Determine if this was an error (prediction != true label)
        predicted_label = 1 if prediction.verdict == "PHISHING" else 0
        is_error = (predicted_label != data.true_label)
        error_type = ""
        
        if is_error:
            if predicted_label == 1 and data.true_label == 0:
                error_type = "FALSE_POSITIVE"
            elif predicted_label == 0 and data.true_label == 1:
                error_type = "FALSE_NEGATIVE"
        
        logger.info(
            f"Feedback received: {feedback_id} | "
            f"Prediction: {data.prediction_id} | "
            f"True Label: {data.true_label} | "
            f"Error: {error_type if is_error else 'CORRECT'}"
        )
        
        # 6. Return success response
        return FeedbackResponse(
            message="Thank you for feedback. Your input helps improve our model!",
            feedback_id=feedback_id,
            will_improve_model=True  # All feedback helps!
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Feedback submission error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Feedback submission failed: {str(e)}"
        )


@router.get("/feedback/stats", response_model=FeedbackStatsResponse)
@limiter.limit("100/minute")
async def get_feedback_stats(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Get statistics on predictions and feedback.
    
    **Purpose:**
    - Monitor model performance based on user feedback
    - Track false positive and false negative rates
    - Measure real-world accuracy (not just test set accuracy)
    - Identify when retraining is needed
    
    **Metrics Returned:**
    1. **total_predictions**: Total predictions made by the model
    2. **total_feedback**: Total feedback submissions received
    3. **false_positives**: Predicted phishing, actually safe
       - These are more serious - legitimate emails blocked
    4. **false_negatives**: Predicted safe, actually phishing
       - These are dangerous - phishing emails get through
    5. **accuracy_from_feedback**: Accuracy based on user feedback
       - Formula: (correct predictions) / (total feedback)
       - Different from test accuracy - this is real-world performance
    
    **How to Use These Stats:**
    - **Low accuracy_from_feedback (<90%)**: Consider retraining
    - **High false_negatives**: Model is too lenient (dangerous!)
    - **High false_positives**: Model is too strict (annoying but safe)
    - **total_feedback < 100**: Need more data before retraining
    
    **Example Response:**
    ```json
    {
        "total_predictions": 1523,
        "total_feedback": 127,
        "false_positives": 8,
        "false_negatives": 3,
        "accuracy_from_feedback": 0.913
    }
    ```
    
    **Interpretation:**
    - Model made 1,523 predictions
    - Users provided feedback on 127 (8.3% feedback rate)
    - Model accuracy: 91.3% on real-world data
    - 8 false positives (blocked 8 legitimate emails)
    - 3 false negatives (missed 3 phishing emails - needs attention!)
    """
    try:
        # Get statistics from database
        stats = DatabaseHelper.get_feedback_stats(db)
        
        # Log statistics
        logger.info(
            f"Feedback Stats: "
            f"Predictions={stats['total_predictions']}, "
            f"Feedback={stats['total_feedback']}, "
            f"FP={stats['false_positives']}, "
            f"FN={stats['false_negatives']}, "
            f"Accuracy={stats['accuracy_from_feedback']}"
        )
        
        # Return response
        return FeedbackStatsResponse(
            total_predictions=stats['total_predictions'],
            total_feedback=stats['total_feedback'],
            false_positives=stats['false_positives'],
            false_negatives=stats['false_negatives'],
            accuracy_from_feedback=stats['accuracy_from_feedback']
        )
        
    except Exception as e:
        logger.error(f"Stats retrieval error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve feedback statistics: {str(e)}"
        )
