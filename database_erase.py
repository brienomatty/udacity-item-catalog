from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem

engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Delete Restaurants if exisitng.
session.query(Restaurant).delete()
# Delete Menu Items if exisitng.
session.query(MenuItem).delete()

allRes = session.query(Restaurant).all()
for i in allRes:
    print(i.name)

print("Your stuff is gone! Muahaha")
