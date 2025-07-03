import xgboost as xgb
import numpy as np

# Load the model
model = xgb.Booster()
model.load_model(r'C:\\Users\\DELL\\Desktop\\authp\\artha_backend-main\\authentication\\xgboost_model.json')

# Define feature names and category names
FEATURE_NAMES = ['user_id', 'income', 'expense', 'expense_to_income_ratio', 'category_encoded']
category_names = ['Groceries', 'Dining', 'Shopping', 'Transport', 'Utilities']  # Update with all categories

def predict(features):
    """
    Predict using the XGBoost model.
    :param features: List of input features (must match model's expectations)
    :return: Predicted value, category, and recommendation
    """
    # Convert input features to DMatrix and set feature names
    dmatrix = xgb.DMatrix(np.array([features]), feature_names=FEATURE_NAMES)
    prediction = model.predict(dmatrix)
    
    # Get the category based on the prediction
    category = get_category_from_prediction(features[-1])  # Use the last feature for category encoding
    recommendation = get_recommendation_from_prediction(prediction, category)
    
    return prediction.tolist(), category, recommendation

def get_category_from_prediction(category_encoded):
    """
    Get the category name from the encoded value.
    :param category_encoded: The encoded category value
    :return: Category name
    """
    if isinstance(category_encoded, int) and 0 <= category_encoded < len(category_names):
        return category_names[category_encoded]
    else:
        return "Unknown"

def get_recommendation_from_prediction(prediction, category):
    """
    Get the recommendation message from the prediction.
    :param prediction: The prediction value (probabilities or continuous value)
    :param category: The category of the transaction
    :return: Recommendation message
    """
    if isinstance(prediction, np.ndarray):
        max_prediction = np.max(prediction)
    else:
        max_prediction = prediction[0]
    
    recommendations = []
    if max_prediction > 0.9:
        recommendations.append(f"This transaction in the category '{category}' is categorized as a high expense.")
        recommendations.append("Consider reviewing your purchases and cutting down on unnecessary spending.")
    elif max_prediction > 0.5:
        recommendations.append(f"This transaction in the category '{category}' is a moderate expense.")
        recommendations.append("Try to manage this category by setting a budget.")
    else:
        recommendations.append(f"This transaction in the category '{category}' is within a reasonable expense range.")
        recommendations.append("You might consider investing the surplus to grow your wealth.")
    
    return " ".join(recommendations)
