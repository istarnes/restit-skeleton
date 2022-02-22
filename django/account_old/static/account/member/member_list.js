Backbone.Pages.Members = Backbone.Mobile.TableGridPage.extend({
	options: {
		title: null,
		ListItemView: Backbone.View.ListItem,
		list_size: 10,
		GridItemView: Backbone.View.ListItem,
		show_loading: true,
		columns: [
			{label:"username", field:"username"},
			{label:"full name", field:"full_name"},
			{label:"email", field:"email"},
			{label:"phone", field:"metadata.phone"},
			{label:"role", field:"role"},
		],
		CollectionClass: Collections.Membership,
		default_view: "list",
		add_button_label: "Add User",
		title: "Users",
		roles: null
	},

	on_init: function() {
		Backbone.Mobile.TableGridPage.prototype.on_init.call(this);
		this.collection.params.state 
	},

	on_member_added: function(model, resp) {
		this.collection.reset();
		this.collection.fetch();
	},

	on_item_select: function(model) {
		// Backbone.View.MemberEdit.showDialog(model, {title:"Edit User", roles:this.options.roles}, this.on_member_added, this);
		
	},

	context_menu_items: [
		{
			value: "edit",
			label: "Edit Info"
		},
		{
			value: "password",
			label: "Change Password"
		},
		"",
		{
			value: "disable",
			label: "Disable Account"
		}
	],

	form_password: [
		{
			name:"pword",
			label:"New Password",
			type:"password",
			placeholder: "Enter Password",
			columns: 12,
		},

	],

	on_item_click: function(evt) {
		var $el = $(evt.currentTarget);
		var id = $el.data("id");

		if (id) {
			if (this.options.item_page) {
				app.showPage(this.options.item_page, {'group_id':app.group.id, 'member_id':id});
				return ;
			}

			var model = this.collection.get(id);
			// if (item) this.on_item_select(item);
			Backbone.Widgets.ToolTip.showMenu(this.context_menu_items, $(evt.currentTarget), _.bind(function(value){
				if (value == "edit") {
					Backbone.View.MemberEdit.showDialog(model, {title:"Edit User", roles:this.options.roles}, this.on_member_added, this);
				} else if (value == "password") {
					app.showForm("Change Password For " + model.full_name(), 
						this.form_password, 
						{ 
							ok_label: "Save",
							callback: function(dlg, data) {
								if (data.pword.strength() < 3) {
									app.notifyCenter("password strength is weak", 2000);
									return;
								}
								dlg.remove();
								app.showWaiting("saving password")
								model.setPassword(data.pword, function(model, resp){
									app.hideWaiting();
									if (resp.status) {
										app.notifyCenter("password changed", 2000);
									} else {
										app.notifyCenter(resp.error, 5000);
									}
								});
							},
						});
				} else if (value == "disable") {

				}
			}, this));
		}

	},

	on_add: function(evt) {
		Backbone.View.MemberEdit.showDialog(null, {title:"New User", roles:this.options.roles}, this.on_member_added, this);
	},

	on_group_change: function(group) {
		if (this.collection && app.group) this.collection.url = "/rpc/account/members/" + app.group.id;
	},

});