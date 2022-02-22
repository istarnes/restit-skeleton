VIDI.statistic = {
	listBlog: function(data, opts) {
		data = data || {};
		opts = opts || {};
		opts.onSuccess = opts.onSuccess || TWIN.REST._genericOnSuccess(opts);
		opts.onFail = opts.onFail || TWIN.REST._genericOnFail(opts);

		TWIN.REST.get("/statistic/list", data, opts.onSuccess, opts.onFail);
		return false;
	}
};
