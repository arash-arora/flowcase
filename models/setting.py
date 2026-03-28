from __init__ import db

class Setting(db.Model):
	key = db.Column(db.String(100), primary_key=True)
	value = db.Column(db.String(255), nullable=True)

	@classmethod
	def get(cls, key, default=None):
		setting = cls.query.filter_by(key=key).first()
		if setting:
			return setting.value
		return default

	@classmethod
	def set(cls, key, value):
		setting = cls.query.filter_by(key=key).first()
		if setting:
			setting.value = str(value)
		else:
			setting = cls(key=key, value=str(value))
			db.session.add(setting)
		try:
			db.session.commit()
		except Exception:
			db.session.rollback()
