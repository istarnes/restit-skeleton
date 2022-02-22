VIDI.notification = {
	kinds: function(listOpts, opts) {
		/*
		 * listOpts: dict of restList options
		 *
		 * Return: active notification kinds
		 */
		opts = opts || {};
		opts.onSuccess = opts.onSuccess || TWIN.REST._genericOnSuccess(opts);
		opts.onFail = opts.onFail || TWIN.REST._genericOnFail(opts);

		TWIN.REST.get("/notification/kinds", listOpts, opts.onSuccess, opts.onFail);
		return false;
	},
	getAllSettings: function(listOpts, opts) {
		/*
		 * listOpts: dict of:
		 * listOpts.user: id or username -- override default user (admin only)
		 * listOpts.kinds: comma separated list of kinds to return (default returns all)
		 *
		 * Return: all notification settings
		 */
		opts = opts || {};
		opts.onSuccess = opts.onSuccess || TWIN.REST._genericOnSuccess(opts);
		opts.onFail = opts.onFail || TWIN.REST._genericOnFail(opts);

		TWIN.REST.get("/notification/settings", listOpts, opts.onSuccess, opts.onFail);
		return false;
	},
	getSetting: function(id_or_name, listOpts, opts) {
		/*
		 * id_or_name: id or name of setting to get
		 * listOpts: dict of:
		 * listOpts.user: id or username -- override default user (admin only)
		 *
		 * Return: requested notification setting
		 */
		opts = opts || {};
		opts.onSuccess = opts.onSuccess || TWIN.REST._genericOnSuccess(opts);
		opts.onFail = opts.onFail || TWIN.REST._genericOnFail(opts);

		TWIN.REST.get("/notification/settings/" + id_or_name, listOpts, opts.onSuccess, opts.onFail);
		return false;
	},
	setSetting: function(id_or_name, listOpts, opts) {
		/*
		 * id_or_name: id or name of setting to change
		 * listOpts.web:     <1|true|yes|0|false|no|(unspecified)>: settings
		 * listOpts.email:   <1|true|yes|0|false|no|(unspecified)>: settings
		 * listOpts.sms:     <1|true|yes|0|false|no|(unspecified)>: settings
		 *
		 * Return: status
		 */
		opts = opts || {};
		opts.onSuccess = opts.onSuccess || TWIN.REST._genericOnSuccess(opts);
		opts.onFail = opts.onFail || TWIN.REST._genericOnFail(opts);

		TWIN.REST.postStatus("/notification/settings/" + id_or_name, listOpts, opts.onSuccess, opts.onFail);
		return false;
	},
	list: function(listOpts, opts) {
		/*
		 * listOpts.user:    <id|username|'me'> (default=me) (staff only)
		 * listOpts.read:    <1|true|yes|0|false|no|-1|both|either|(unspecified)> (default=both): filter by read status
		 * listOpts.deleted: <1|true|yes|0|false|no|-1|both|either|(unspecified)> (default=both): filter by deleted status
		 * listOpts.kinds:   <kind,kind,...> (default=all)
		 *
		 * Return: list user's notifications
		 */
		opts = opts || {};
		opts.onSuccess = opts.onSuccess || TWIN.REST._genericOnSuccess(opts);
		opts.onFail = opts.onFail || TWIN.REST._genericOnFail(opts);

		TWIN.REST.get("/notification/list", listOpts, opts.onSuccess, opts.onFail);
		return false;
	},
	getUnreadCount: function(opts) {
		/*
		 * Return: count of current user's notifications
		 */
		opts = opts || {};
		opts.onSuccess = opts.onSuccess || TWIN.REST._genericOnSuccess(opts);
		opts.onFail = opts.onFail || TWIN.REST._genericOnFail(opts);
		
		TWIN.REST.get("/notification/unread", {}, opts.onSuccess, opts.onFail);
	},
	markRead: function(notification_id, opts) {
		/*
		 * notification_id: notification_id to mark as read
		 *
		 * Return: status
		 */
		opts = opts || {};
		opts.onSuccess = opts.onSuccess || TWIN.REST._genericOnSuccess(opts);
		opts.onFail = opts.onFail || TWIN.REST._genericOnFail(opts);

		TWIN.REST.postStatus("/notification/read/" + notification_id, {}, opts.onSuccess, opts.onFail);
		return false;
	}
};

