from app import create_app
from extensions import db
from model import CategoryThreshold

app = create_app()

with app.app_context():
    default_thresholds = [
        {"category": "Rent/Mortgage", "threshold": 0.30},
        {"category": "Car Insurance", "threshold": 0.10},
        {"category": "Phone Bill", "threshold": 0.05},
        {"category": "Electricity", "threshold": 0.10},
        {"category": "Groceries", "threshold": 0.15},
        {"category": "Eating Out", "threshold": 0.05},
        {"category": "Savings", "threshold": 0.20},
    ]
    for threshold in default_thresholds:
        db.session.add(CategoryThreshold(**threshold))
    db.session.commit()
    print("Default thresholds added.")
