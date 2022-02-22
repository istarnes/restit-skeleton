Backbone.Pages.ChangePassword = Backbone.Mobile.Dialog.extend({
	template: '<form role=form style=width:500px><div class=form-group><label for=password>Old Password</label><input class=form-control id=oldpassword name=oldpassword placeholder="Enter Old Password"type=password></div><div class=form-group><label for=password>New Password</label><input class=form-control id=password name=password placeholder="Enter New Password"type=password></div><div class=form-group><label for=password>Confirm New Password</label><input class=form-control id=password2 name=password2 placeholder="Enter Password Again"type=password></div><h4 id=password-strength></h4><hr><div class="button-bar text-right"><button class="btn btn-primary save"type=submit>SAVE</button> <button class="btn btn-cancel cancel"type=button>CANCEL</button></div></form>',

	events: {
		"submit form": "on_save",
		"click button.cancel": "remove",
		"keyup input#password": "on_keyup_password"
	},

	pre_render: function() {
		var desc = new Array();
		desc[0] = "Very Weak (not strong enough)";
		desc[1] = "Weak (not strong enough)";
		desc[2] = "Weak";
		desc[3] = "Medium";
		desc[4] = "Strong";
		desc[5] = "Strongest";
		this.desc = desc;

		var bClass = new Array();
		bClass[0] = "has-error";
		bClass[1] = "has-error";
		bClass[2] = "has-warning";
		bClass[3] = "has-success";
		bClass[4] = "has-success";
		bClass[5] = "has-success";

		this.bClass = bClass;
	},

	on_keyup_password: function(evt) {
		var s = this.$pwd.val().strength();
		this.$password_strength.text(this.desc[s]);
		this.$pwd.removeClass("has-error has-warning has-success").addClass(this.bClass[s]);
	},

	on_saved: function(model) {
		window.app.hideWaiting();
		this.dlg.remove();

		if (this.callback) {
			this.callback(model);
		} else {
			app.notifyCenter("Password Changed", 2000);
		}
	},

	on_error: function(model, error) {
		window.app.hideWaiting();
		window.app.error("Error", error);
	},

	on_save: function(evt) {
		evt.preventDefault();
		var $form = this.$el.find("form");
		var data =	Backbone.Form.getData($form, {checkbox_truefalse:true});
		var s = data.password.strength();
		if (s < 2) {
			this.$password_strength.text("PASSWORD IS NOT STRONG ENOUGH!");
			evt.preventDefault();
			return false;
		}

		if (data.password != data.password2) {
			this.$password_strength.text("PASSWORD DO NOT MATCH!");
			evt.preventDefault();
			return false;
		}

		window.app.showWaiting();

		window.app.me.save({oldpassword:data.oldpassword, newpassword:data.password}, {success:_.bind(this.on_saved, this),
		                                                                               error:_.bind(this.on_error, this)});
	},

	post_render: function() {
		this.$password_strength = this.$el.find("#password-strength");
		this.$pwd = this.$el.find("input#password");
	}

});