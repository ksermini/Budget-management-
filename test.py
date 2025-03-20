from app import create_app, db
from model import UserBudget, CategoryThreshold
import pandas as pd

# Create the Flask app
app = create_app()

# Run the test code inside the application context
with app.app_context():
    # Fetch data using a valid SQLAlchemy statement
    user_budget_query = db.session.query(UserBudget).statement
    thresholds_query = db.session.query(CategoryThreshold).statement

    # Read user budget data
    try:
        user_budget = pd.read_sql(user_budget_query, con=db.session.bind)
        print("User Budget Data:")
        print(user_budget)
    except Exception as e:
        print(f"Error fetching user budget: {str(e)}")

    # Read category thresholds data
    try:
        thresholds = pd.read_sql(thresholds_query, con=db.session.bind)
        print("Threshold Data:")
        print(thresholds)
    except Exception as e:
        print(f"Error fetching thresholds: {str(e)}")
