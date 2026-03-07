from __init__ import create_app, db
from models.droplet import Droplet, DropletInstance
from datetime import datetime, timedelta

app = create_app()
with app.app_context():
    d = Droplet(display_name='test', droplet_type='container')
    db.session.add(d)
    db.session.commit()
    inst = DropletInstance(droplet_id=d.id, user_id='u1')
    inst.updated_at = datetime.utcnow() - timedelta(minutes=31)
    db.session.add(inst)
    db.session.commit()
    print('Added stale instance', inst.id)
    from routes.droplet import cleanup_stale_instances
    cleanup_stale_instances()
    print('After cleanup, count', DropletInstance.query.count())
