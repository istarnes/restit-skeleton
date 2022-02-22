Backbone.Views = Backbone.Views || {};

var login_form_template = "<form action='/login' id='login'><div class='row'>";
login_form_template += "<input name='username' id='username' type='text' placeholder='username or email'/></div>";
login_form_template += "<div class='row'><input name='password' id='password' type='password' placeholder='password'/></div>";
login_form_template += "<div class='row'><a id='forgot' href='/forgot'>Forgot your password?</a></div></form>";
Backbone.Views.Login = Backbone.View.Dialog.extend({
	events: {
		"click a#forgot": "on_click_forgot"
	},

	on_click_forgot: function(evt) {
		evt.preventDefault();
		this.remove();
		Views.Forgot.popup();
		return false;
	}

},{
	popup: function(options) {
		options = options || {};
		options = _.extend({
			title: "Sign In",
			form: login_form_template,
			modal: true,
			modal_bg_close: false,
			dialog_close: false,
			buttons: [{label:"Sign In", classes:"default"},
				{label:"Cancel", classes:"cancel"}]
		}, options);

		var dialog = new this(options);
		dialog.$el.addClass('confirm login');
		return dialog.display(options);
	}
});

var forgot_form_template = "<form action='/login' id='login'><div class='row'>";
forgot_form_template += "<input name='username' id='username' type='text' placeholder='email'/></div></form>";
Backbone.Views.Forgot = Backbone.View.Dialog.extend({

},{
	popup: function(options) {
		options = options || {};
		options = _.extend({
			title: "Reset my password",
			form: forgot_form_template,
			modal: true,
			modal_bg_close: false,
			dialog_close: false,
			buttons: [{label:"Reset", classes:"default"},
				{label:"Cancel", classes:"cancel"}]
		}, options);

		var dialog = new this(options);
		dialog.$el.addClass('confirm login');
		return dialog.display(options);
	}
});
