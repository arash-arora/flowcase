from __init__ import db

class Permissions:
	ADMIN_PANEL = "perm_admin_panel"
	VIEW_INSTANCES = "perm_view_instances"
	EDIT_INSTANCES = "perm_edit_instances"
	VIEW_USERS = "perm_view_users"
	EDIT_USERS = "perm_edit_users"
	VIEW_DROPLETS = "perm_view_droplets"
	EDIT_DROPLETS = "perm_edit_droplets"
	VIEW_REGISTRY = "perm_view_registry"
	EDIT_REGISTRY = "perm_edit_registry"
	VIEW_GROUPS = "perm_view_groups"
	EDIT_GROUPS = "perm_edit_groups"

	@staticmethod
	def check_permission(userid, permission):
		from models.user import User, Group
		
		#go through all groups and check if the user has the permission
		user = User.query.filter_by(id=userid).first()
		groups = user.groups.split(",")

		for group in groups:
			group = Group.query.filter_by(id=group).first()
	
			if not group: #group not found, most likely deleted
				continue

			if getattr(group, permission):
				return True
		return False

	@staticmethod
	def user_in_groups(userid, allowed_groups_csv):
		"""
		Check if a user belongs to any of the allowed groups.
		
		Args:
			userid: User ID to check
			allowed_groups_csv: Comma-separated string of group IDs, or empty/None for public access
			
		Returns:
			True if user is in any allowed group, or if allowed_groups_csv is empty/None (public)
		"""
		# If allowed_groups is empty or None, droplet is public
		if not allowed_groups_csv or allowed_groups_csv.strip() == "":
			return True
		
		from models.user import User, Group
		
		user = User.query.filter_by(id=userid).first()
		if not user:
			return False
		
		# Get user's group IDs
		user_groups = set(g for g in [g.strip() for g in user.groups.split(",")] if g)
		
		# Parse allowed groups tokens and normalize them to IDs where possible.
		allowed_tokens = [t.strip() for t in allowed_groups_csv.split(",") if t.strip()]
		allowed_ids = set()
		for token in allowed_tokens:
			# Try to find group by id first
			group = Group.query.filter_by(id=token).first()
			if group:
				allowed_ids.add(group.id)
				continue
			# Fall back to matching by display_name (case-sensitive as stored)
			group = Group.query.filter_by(display_name=token).first()
			if group:
				allowed_ids.add(group.id)
			else:
				# If token doesn't match any group, add the raw token so we still support legacy values
				allowed_ids.add(token)
		
		# Check if user is in any allowed group
		return bool(user_groups & allowed_ids)