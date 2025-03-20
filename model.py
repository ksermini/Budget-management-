from extensions import db  # Import db from extensions.py
from datetime import datetime

class JournalEntry(db.Model):
    __tablename__ = 'journal_entries'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Link to User
    user = db.relationship('User', backref=db.backref('journal_entries', lazy=True))  # Relationship to User
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<JournalEntry {self.title}>'


class User(db.Model):
    __tablename__ = 'user'  # Specifies the table name

    # Define the columns for the 'user' table
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Primary key
    email = db.Column(db.String(255), unique=True, nullable=False)  # Email field, unique and required
    password = db.Column(db.String(255), nullable=False)  # Password field, required (hashed)
    description = db.Column(db.Text, nullable=True)  # Description field, optional text
    admin = db.Column(db.Boolean, default=False, nullable=False)  # Admin field, boolean, default is False

    # String representation of the User object for debugging
    def __repr__(self):
        return f'<User {self.email}>'
# User table
class UserBudget(db.Model):
    __tablename__ = 'user_budget'
    __table_args__ = {'extend_existing': True}  # Allow redefinition

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, nullable=False)  # Adjusted to match `user_id` from payload
    month = db.Column(db.String(7), nullable=False)
    monthly_income = db.Column(db.Float, nullable=False)
    rent_mortgage = db.Column(db.Float, nullable=False, default=0)
    car_insurance = db.Column(db.Float, nullable=False, default=0)
    groceries = db.Column(db.Float, nullable=False, default=0)
    eating_out = db.Column(db.Float, nullable=False, default=0)
    transportation = db.Column(db.Float, nullable=False, default=0)
    entertainment = db.Column(db.Float, nullable=False, default=0)
    savings = db.Column(db.Float, nullable=False, default=0)
    phone_bill = db.Column(db.Float, nullable=False, default=0)
    electricity = db.Column(db.Float, nullable=False, default=0)
    wifi = db.Column(db.Float, nullable=False, default=0)
    miscellaneous = db.Column(db.Float, nullable=False, default=0)
    # Optional: thresholds if needed
    #thresholds = db.Column(db.JSON, nullable=True)  # JSON column for thresholds


# Chatroom table
class Chatroom(db.Model):
    __tablename__ = 'chatroom'  # Specifies the table name

    # Define the columns for the 'chatroom' table
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Primary key
    name = db.Column(db.String(255), nullable=False)  # Name field, required
    description = db.Column(db.Text, nullable=True)  # Description field, optional text

    # String representation of the Chatroom object for debugging
    def __repr__(self):
        return f'<Chatroom {self.name}>'


# UserBudget table
# class UserBudget(db.Model):
#     __tablename__ = 'user_budget'  # Specifies the table name

#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Primary key
#     category = db.Column(db.String(255), nullable=False, index=True)  # Indexed for performance
#     amount = db.Column(db.Float, nullable=False)  # Amount cannot be null

#     # String representation of the UserBudget object for debugging
#     def __repr__(self):
#         return f'<UserBudget {self.category}: {self.amount}>'


# CategoryThreshold table
class CategoryThreshold(db.Model):
    __tablename__ = 'category_thresholds'  # Specifies the table name

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Primary key
    category = db.Column(db.String(255), nullable=False, index=True)  # Indexed for performance
    threshold = db.Column(db.Float, nullable=False)  # Threshold cannot be null

    # String representation of the CategoryThreshold object for debugging
    def __repr__(self):
        return f'<CategoryThreshold {self.category}: {self.threshold}>'
