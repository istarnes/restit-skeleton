CloudIt.Pages.Login = Backbone.Mobile.Page.extend({
	template:"account.login",
	id: "login_page",

	events: {
		"submit form": "on_submit",
		"click a#reset_pwd": "on_reset"
	},

	on_reset: function(evt) {
		window.app.input("Reset Password", null, "Enter your email address", function(dlg){
				var email = dlg.getValue();
				if (email.isEmail()) {
					window.app.showWaiting();
					window.app.me.forgotPassword(email, function(model, err){
						window.app.hideWaiting();
						console.log(err);
						window.app.input("Reset Password", "A reset code has been sent to your email address.  Please enter it now.", "Reset Code", function(){

						});
					});
					dlg.remove();
				}				
			});
	},

	on_submit: function(evt) {
		evt.preventDefault();
		var u = this.$el.find("input#username").val();
		var p = this.$el.find("input#password").val();
		var handler = _.bind(this.on_response, this);
		window.app.me.login(u, p, handler, handler);
	},

	on_response: function(model, error) {
		if (error) {
			console.log(error);
			window.app.error("Login Failed", error);
		}
	},

	post_render: function() {
		this.$el.find("input#username").focus();
	},

	on_route: function() {
		window.app.hideHeader();
		this.show();
	}
});