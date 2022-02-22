
Backbone.View.MemberEdit = Backbone.View.extend({
	events: {
		"submit form": "on_save",
		"click button.remove": "on_remove",
		"click button.reset": "on_reset",
		"click button.invite": "on_invite",
		"click button.cancel": "remove",
		"blur input[name='name']": "on_name_change"
	},

	options: {
		invite: true,
		fields:[
			{
				name:"name",
				id: "name",
				label:"Full Name",
				type:"text",
				placeholder:"Enter Full Name",
				columns: 12
			},
			{
				name:"email",
				label:"Email",
				type:"email",
				placeholder:"Enter Email",
				columns: 12
			},
			{
				name:"username",
				label:"Username",
				type:"text",
				placeholder:"Enter Username or leave blank for auto",
				columns: 12
			},
			{
				name:"metadata.phone",
				label:"Phone",
				type:"tel",
				placeholder:"Enter Phone Number",
				columns: 12
			},
		],
		thumbnail_name: "picture",
	},

	on_name_change: function(evt) {
		console.log(this.model);
		var $input = $(evt.currentTarget);
		if (!this.model) {
			$input.val($input.val().trim());
			this.$el.find("input[name='username']").val(this.nameToUsername($input.val()));
		}
	},

	on_remove: function(evt) {
		this.dlg.$el.hide();

		window.app.confirm("Disable Membership", 
		                   "Are you sure you want to disable this account?",
		                   _.bind(function(dlg){
		                     dlg.remove();
		                     this.model.save({state:-100}, {success:_.bind(this.on_saved, this),
		                                                    error:_.bind(this.on_error, this)})
		                     if (this.list_view) this.list_view.reload();
		                     this.remove();
		                   }, this));
	},

	on_reset: function(evt) {
		window.app.showWaiting();
		this.model.save({reset_password:1}, {success:_.bind(this.on_saved, this),
		                                     error:_.bind(this.on_error, this)});
	},

	on_invite: function(evt) {
		window.app.showWaiting();
		this.model.save({resend_invite:1}, {success:_.bind(this.on_saved, this),
		                                    error:_.bind(this.on_error, this)});
	},

	on_resend: function(evt) {
		this.model.save({resent_invite:1}, {success:_.bind(this.on_saved, this),
		                                    error:_.bind(this.on_error, this)});
	},

	getFormData: function() {
		var $form = this.$el.find("form");
		if (!this.image) {
			$form.find("input#thumbnail").remove();
			return Backbone.Form.getData($form);
		}

		$form.find("input#thumbnail").remove();
		
		var formdata = new FormData($form[0]);
		var blobBin = null;
		var img = this.image;
		if (img.toDataURL) {
			blobBin = atob(img.toDataURL().split(',')[1]);
		} else {
			blobBin = atob(img.src.split(',')[1]);
		}
		var array = [];
		for(var i = 0; i < blobBin.length; i++) {
			array.push(blobBin.charCodeAt(i));
		}
		var file=new Blob([new Uint8Array(array)], {type: 'image/png'});
		formdata.append(this.options.thumbnail_name, file, "image.png");

		data = Backbone.Form.getData($form);
		data.__files = {
			formvals: {},
			files: [file]
		};
		data.__files.formdata = formdata;
		return data;
	},

	on_saved: function(model) {
		window.app.hideWaiting();
		this.dlg.remove();
		if (this.callback) this.callback(model);
	},

	on_error: function(model, resp) {
		window.app.hideWaiting();
		this.dlg.remove();
		window.app.error("Error", resp.error);
	},

	nameToEmail: function(name) {
		return name.trim().replaceAll(' ', '.').toLowerCase() + "@" + window.app.group.get("name").replaceAll(' ', '').toLowerCase() + ".invalid";
	},

	nameToUsername: function(name) {
		return name.trim().replaceAll(' ', '.').toLowerCase();
	},

	on_save: function(evt) {
		evt.preventDefault();
		var data = this.getFormData();
		if (data.name) {
			data.name = data.name.trim()
			var names = data.name.split(' ');
			data.first_name = names.shift();
			data.last_name = names.join(' ')
			// delete data.name;
		}

		if (!data.username) {
			data.username = this.nameToUsername(data.name);
		}

		if (data.fakeuser) {
			delete data.fakeuser;
		}
		if (data.fakepwd) {
			delete data.fakepwd;
		}

		if (data.fkuser) {
			delete data.fkuser;
		}
		if (data.fkpassword) {
			delete data.fkpassword;
		}

		if (data.password) {
			data.password2 = data.password;
		} else {
			delete data.password;
		}

		if (data.email && (data.email.indexOf("@"))) {
			// data
		} else if (data.email != undefined) {
			delete data.email;
		} else {
			data.email = this.nameToEmail(data.name);
		}

		if (data.phone && data.phone.length) {
			data.phone = data.phone.removeAll(".").removeAll('-').removeAll('(').removeAll(')').removeAll(' ');
		}

		if (!data.name && !data.email) {
			return false;
		}

		if (!this.model) {
			
			if (this.options.group) {
				this.model = new Backbone.Model();
				this.model.url = "/rpc/account/group/invite/" + this.options.group.id;
			} else {
				this.model = new Models.User();
			}
			// data.isnew = "yes";
			
		}
		window.app.showWaiting();
		console.log(data);
		this.model.save(data, {success:_.bind(this.on_saved, this),
													 error:_.bind(this.on_error, this)});
	},

	has_roles: function() {
		return this.options.roles && this.options.roles.length;
	},

	render_self: function() {
		this.undelegateEvents();
		var defaults = this.options.defaults;
		var $form = $('<form role="form" />');//.css("width", "500px");
		$form.attr("autocomplete", "off");

		var $row = $("<div />").addClass("row").appendTo($form);
		var $col1 = $("<div />").addClass("col-md-4").appendTo($row);
// <input name="picture" type="file" id="thumbnail" class="thumbnail-picker thumbnail-picker-md" 
// data-label="change" {{#model.thumbnail}}data-image="{{model.thumbnail}}" {{/model.thumbnail}}>
		var $imginput = $("<input />")
			.prop('name', 'picture')
			.prop('type', 'file')
			.prop('id', 'thumbnail')
			.addClass('thumbnail-picker thumbnail-picker-md')
			.data("label", "change");

		if (this.model) {
			var url = this.model.get("thumbnail");
			if (url) {
				$imginput.data("image", url);
			}

			// defaults = {
			// 	email:this.model.get('email'),
			// 	name:this.model.full_name(),
			// 	"metadata.phone":this.model.get('metadata.phone'),
			// 	username:this.model.get('username')
			// }
		}


		$("<div />").addClass("member-avatar").append($imginput).appendTo($col1);


		var $col2 = $("<div />").addClass("col-md-8").appendTo($row);
		Backbone.Form.build(this.options.fields, defaults, $col2, this.model);
		this.$el.html( $form );
		this.post_render();
		this.delegateEvents();
	},

	post_render: function() {
		if (this.model) {
			this.$el.find("select#role").val(this.model.get("role"));

			if (this.model.id != window.app.me.id) {
				if (!window.app.me.isStaff() && !window.app.me.isManager()) {
					this.$el.find("input#email").attr('disabled','disabled');
					this.$el.find("select#role").attr('disabled','disabled');
				}
			}
		}

		if (window.loadImage) {
			var self = this;
			this.$el.find("input#thumbnail").InputImage().on("image", function(evt, image){
				self.$el.parents(".dialog").removeClass("grow").removeClass("slideDown").addClass("shrink");

				var editor = Backbone.Dialog.ImageEditor.editImage(image, {
					crop: true,
					aspectRatio: 1.0,
					on_done: function(editor, edited_image){
						self.image = edited_image;
						self.$el.find(".inputimage img").attr("src", editor.getImageAsDataURL());
						self.$el.parents(".dialog").removeClass("shrink").addClass("grow");
					},
					on_cancel: function() {
						self.$el.parents(".dialog").removeClass("shrink").addClass("grow");
					}
				});
			});
		} else {
			this.$el.find("input#thumbnail").InputImage();
		}

		this.$el.find("select").selectpicker();
	}

}, {
	showDialog: function(model, options, callback, context) {
		if (_.isFunction(options)) {
			callback = options;
			context = callback;
			options = {title:"Edit Profile"};
		} else {
			options = _.extend({title:"Edit Profile"}, options);
		}
		var frm = new this(options);
		frm.model = model;
		if (context) callback = _.bind(callback, context);
		frm.callback = callback;
		frm.dlg = Backbone.View.Dialog.form(options.title, frm, {minWidth: 800});
		return frm;
	}
}
);

// CloudIt.Dialogs.MemberEdit = CloudIt.Pages.MemberEdit.extend(
// 	Backbone.View.Dialog.prototype
// );
