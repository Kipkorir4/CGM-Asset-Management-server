from app import app, db  # Import the app and db from your main application file
from models import Budget

# Push the application context to allow interaction with the database
with app.app_context():
    # Example budget initialization with higher amounts
    categories = [
        {'category': 'Water', 'total_budget': 2000000.0},
        {'category': 'Electricity', 'total_budget': 3000000.0},
        {'category': 'Plumbing', 'total_budget': 1600000.0},
        {'category': 'Wi-Fi', 'total_budget': 100000.0},
        {'category': 'Fenestration', 'total_budget': 1200000.0},
        {'category': 'Paint', 'total_budget': 800000.0},
    ]

    # Delete existing budgets to reinitialize them
    db.session.query(Budget).delete()
    
    for cat in categories:
        budget = Budget(category=cat['category'], total_budget=cat['total_budget'], balance=cat['total_budget'])
        db.session.add(budget)

    db.session.commit()
    print("Budgets reinitialized successfully")
