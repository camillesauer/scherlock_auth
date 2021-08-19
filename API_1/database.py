from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from conf import mysql_user, mysql_password, new_database_name

engine = create_engine('mysql+mysqlconnector://{0}:{1}@localhost/{2}'.format(mysql_user, mysql_password, new_database_name))

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
