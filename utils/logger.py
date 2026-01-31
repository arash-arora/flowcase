import time
from __init__ import db

def log(level: str, message: str):
	"""Log a message to the database and console"""
	from models.log import Log
	
	from sqlalchemy.orm import Session
	
	timestamp = None
	try:
		# Use a separate connection/session to avoid messing with the main transaction
		# or failing if the main transaction is in a broken state
		with db.engine.connect() as connection:
			with Session(bind=connection) as session:
				log_entry = Log(level=level, message=message)
				session.add(log_entry)
				session.commit()
				timestamp = log_entry.created_at.strftime('%Y-%m-%d %H:%M:%S')
	except Exception as e:
		print(f"FAILED TO LOG TO DB: {message} | Error: {e}", flush=True)
		import datetime
		timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	
	# Only print DEBUG logs if in debug mode
	from config.config import parse_args
	args = parse_args()
	
	if level != "DEBUG" or args.debug:
		print(f"[{level}] | {timestamp} | {message}", flush=True)
		
	return log_entry 
