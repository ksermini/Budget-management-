import pandas as pd
from sqlalchemy import create_engine

class BudgetCalculator:
    THRESHOLDS = {
        'Rent/Mortgage': 0.30,
        'Car Insurance': 0.10,
        'Groceries': 0.15,
        'Eating Out': 0.10,
        'Transportation': 0.10,
        'Entertainment': 0.10,
        'Savings': 0.20,
        'Phone Bill': 0.05,
        'Electricity': 0.10,
        'WiFi': 0.05,
        'Miscellaneous': 0.05,
    }

    @staticmethod
    def analyze_budget(data):
        """
        Analyzes budget data, calculates thresholds, flags categories,
        and prepares the DataFrame for storage or display.
        
        Args:
            data (list): List of dictionaries containing 'category' and 'amount'.

        Returns:
            pd.DataFrame: Processed DataFrame with analysis results.
        """
        # Convert input data to DataFrame
        df = pd.DataFrame(data)
        df.columns = ['category', 'amount']

        # Ensure "Monthly Income" exists
        if "Monthly Income" not in df['category'].values:
            raise ValueError("Monthly Income is required for analysis.")

        # Calculate total income
        total_income = df[df['category'] == 'Monthly Income']['amount'].values[0]
        if total_income <= 0:
            raise ValueError("Monthly Income must be greater than zero.")

        # Convert thresholds to DataFrame
        thresholds_df = pd.DataFrame(list(BudgetCalculator.THRESHOLDS.items()), columns=['category', 'threshold'])

        # Merge thresholds with input data
        result_df = pd.merge(df, thresholds_df, on="category", how="left")

        # Perform calculations
        result_df['ratio'] = result_df['amount'] / total_income
        result_df['flag'] = result_df['ratio'] > result_df['threshold']

        # Add timestamp for storage
        result_df['timestamp'] = pd.Timestamp.utcnow()

        return result_df

    @staticmethod
    def store_analysis_to_db(result_df, db_engine):
        """
        Stores the analysis results to the database for historical tracking.
        
        Args:
            result_df (pd.DataFrame): DataFrame with analysis results.
            db_engine: SQLAlchemy engine for database connection.
        """
        result_df.to_sql('budget_analysis_history', con=db_engine, if_exists='append', index=False)
