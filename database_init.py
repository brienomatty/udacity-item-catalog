from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem

engine = create_engine('sqlite:///restaurantmenu.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create fake restaurants
Restaurant1 = Restaurant(name="Timmy's BBQ")
session.add(Restaurant1)
session.commit()

Restaurant2 = Restaurant(name="Rodney's Chili")
session.add(Restaurant2)
session.commit()

# Populate a restaurant with menu items for testing
Item1 = MenuItem(name="BBQ Chicken",
                 description="It's chicken, dawg.",
                 price="3.49",
                 course="main",
                 restaurant=Restaurant1)
session.add(Item1)
session.commit()

Item2 = MenuItem(name="Pulled Pork",
                 description="The best ever.",
                 price="9.99",
                 course="main",
                 restaurant=Restaurant1)
session.add(Item2)
session.commit()

Item3 = MenuItem(name="Chili Bowl",
                 description="Bowls are better than cups or plates.",
                 price="64.89",
                 course="all",
                 restaurant=Restaurant2)
session.add(Item3)
session.commit()

print("Your database has been populated with fake data!")
