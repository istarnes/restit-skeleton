Models.User = Backbone.Model.extend({
    urlRoot: '/rpc/account/member/',

    login: function(username, password, callback) {
        console.log("me.login");
        var h = _.bind(function(model, resp){
            if (!resp.error) {
                this.attributes = model.attributes;
                // console.log("fire change event");
                this.attributes.password = "";
                this.trigger("change", this);
            }
            if (callback) {
                this.attributes.password = "";
                callback(this, resp);
            }
        }, this);
        this.post("/rpc/account/login", {graph:"detailed", username:username, password:password}, h, h);
    },

    cardLogin: function(pan, pin, callback, context) {
        console.log("me.login");
        if (context) callback = _.bind(callback, context);
        var h = _.bind(function(model, resp){
            if (!resp.error) {
                this.attributes = model.attributes;
                // console.log("fire change event");
                this.attributes.password = "";
                this.trigger("change", this);
            }
            if (callback) {
                this.attributes.password = "";
                callback(this, resp);
            }
        }, this);
        this.post("/rpc/account/login", {graph:"detailed", pan:pan, pin:pin}, h, h);
    },

    tokenLogin: function(invite_token, callback, context) {
        console.log("me.login");
        if (context) callback = _.bind(callback, context);
        var h = _.bind(function(model, resp){
            if (!resp.error) {
                this.attributes = model.attributes;
                // console.log("fire change event");
                this.attributes.password = "";
                this.trigger("change", this);
            }
            if (callback) {
                this.attributes.password = "";
                callback(this, resp);
            }
        }, this);
        var data = {graph:"detailed"};
        if (_.isObject(invite_token)) {
            data = _.extend({}, data, invite_token);
        } else {
            data.invite_token = invite_token;
        }
        this.post("/rpc/account/login", data, h, h);
    },

    logout: function(callback) {
        console.log("me.logout");
        var h = _.bind(function(model, resp){
            if (!resp.error) {
                this.id = null;
                this.atrributes = {};
                this.trigger("change", this);
            }
            if (callback) {
                callback(this, resp);
            }
        }, this);
        this.post("/rpc/account/logout", {}, h, h);
    },

    unlock: function(callback, context) {
        this.save({action:"unlock"}, callback, context);
    },

    changePassword: function(current, password, callback, context) {
        if (context) callback = _.bind(callback, context);
        this.post("/rpc/account/password_change", {"username":username, "current_pword":current, "password":password}, callback);
    },

    setPassword: function(password, callback, context) {
        this.save({password:password, password2:password}, callback, context)
    },

    checkStatus: function(callback, context) {
        if (context) callback = _.bind(callback, context);
        this.fetch(callback);
    },

    forgotPassword: function(username, callback) {
        this.post("/rpc/account/forgot", {"username":username, "use_code":1}, callback, callback);
    },

    getDefaultMembership: function() {
        if (!this.attributes.default_membership || !this.attributes.default_membership.org) {
            return this.attributes.memberships[0];
        }
        return this.attributes.default_membership;
    },

    isMe: function() {
        if (window.app.me) {
            return (window.app.me.id === this.id);
        }
        return false;
    },

    isSuperUser: function() {
        return this.attributes.is_superuser;
    },

    isStaff: function() {
        return this.attributes.is_staff;
    },

    is_staff: function() {
        return this.attributes.is_staff;
    },

    isManager: function() {
        if (this.isStaff()) return true;
        if (this.membership && this.membership.isManager()) return true;
        return false;
    },

    hasPerm: function(perm) {
        if (_.isArray(perm)) {
            var i=0;
            for (; i < perm.length; i++) {
                if (this.hasPerm(perm[i])) return true;
            }
            return false;
        }
        if ((perm == "staff")&&(this.isStaff())) return true;
        if (this.get("metadata.permissions." + perm)) return true;
        if (this.membership) return this.membership.hasPerm(perm);
        return false;
    },

    linkAuthCard: function(pan, pin, callback, context) {
        if (pin == undefined) pin = null;
        this.post("/rpc/account/linkcard", {"pan":pan, "pin":pin}, callback, context);
    },

    link: function(backend, callback) {
        var platform = backend;
        if (platform == "linkedin-oauth2") platform = "linkedin";
        if (backend == "linkedin") backend = "linkedin-oauth2";

        if (window.is_native) {
            window.login_complete = callback;
            window.app.on("social:linked", _.bind(function(splat){
                console.log("caught - social_link_complete");
                window.app.me.fetch({success:function(){
                    callback(platform, window.app.me.hasSocialLink(platform));
                }});
                window.app.off("social:linked");
            }, this));
            return window.app.sendNativeActionWithDelay("link."+backend);
        }

        var url =  "//" + window.location.host + "/login/" + backend + "/?next=/close";
        Backbone.Social.openDialog(url, "link_account", 600, 440, function(evt){
            window.app.me.fetch({success:function(){
                callback(backend, window.app.me.hasSocialLink(platform));
            }});
        });
    },

    unlink: function(backend, callback) {
        var platform = backend;
        if (backend == "linkedin") backend = "linkedin-oauth2";

        Backbone.Model.post("/rpc/account/unlink/" + backend, {
            "backend": backend
        }, function(){
            window.app.me.fetch({success:function(){
                callback(backend, window.app.me.hasSocialLink(platform));
            }});
        }, function() {
            callback(platform, false);
        });
    },

    initials: function() {
        if (this.get("last_name")) {
           return this.get("first_name")[0] + this.get("last_name")[0]; 
        }
        return "";
    },

    full_name: function() {
        var res = this.get("first_name") + " " + this.get("last_name");
        if (res.length > 2) return res;
        return this.get("username");
    },

    getFullName: function() {
        return this.get("first_name") + " " + this.get("last_name");
    },

    name: function() {
        if (!this.get("first_name") && !this.get("last_name")) return this.get("username");
        return this.get("first_name") + " " + this.get("last_name");
    },

    hasRole: function(role) {
        if (this.isStaff()) return true;
        if (this.membership) {
            return this.membership.hasRole(role);
        }
        return _.contains(this.attributes.roles, role);
    },

    has_avatar: function() {
        return this.attributes.profile_image;
    },

    fetchPicture: function() {
        this.params.get_picture = 1;
        this.fetch({
            success: function(model) {
                delete this.params.get_picture;
            }
        });
    },

    // thumbnail: function() {
    //     if (this.attributes.thumbnail) {
    //         return this.attributes.thumbnail;
    //     }
    //     return window.STATIC_URL + "img/user.png";
    // },

    profile_image: function() {
        if (this.attributes.profile_image) {
            return this.attributes.profile_image;
        }
        return window.STATIC_URL + "img/user.png";
    },

    toggleFollow: function(success, error) {
        if (this.get("amFollowing")) {
            this.unfollow(success, error);
        } else {
            this.follow(success, error);
        }
    },

    follow: function(success, error) {
        this.attributes.amFollowing = true;
        Backbone.Model.post("/rpc/account/" + this.id + "/follow", {}, success, error);
    },

    unfollow: function(success, error) {
        this.attributes.amFollowing = false;
        Backbone.Model.post("/rpc/account/" + this.id + "/unfollow", {}, success, error);
    },

    isMale: function() {
        return (this.get("info.gender") == "male");
    },

    logToFeed: function(action, component, key, success, error) {
        Backbone.Model.post("/rpc/account/" + this.id + "/feed", 
            {action:action, component:component, key:key}, 
            success, error);        
    },

    hasSocialLink: function(backend) {
        return _.isObject(this.get("social."+backend));
    },

    getSocialSetting: function(platform, setting) {
        return this.get("metadata.social." + platform + "_" + setting);
    },

    get_attrs: {
        is_approver: function() {
            return this.hasRole('approver');
        }
    }
},
{
    ChangePassword: function(username, current, password, callback, context) {
        if (context) callback = _.bind(callback, context);
        Backbone.Model.post("/rpc/account/password_change", {"username":username, "current_pword":current, "password":password}, callback);
    }
});

Collections.User = Backbone.Collection.extend({
    Model: Models.User
});

Models.Membership = Backbone.Model.extend({
    urlRoot: '/rpc/account/membership',

    translate: {
        "metadata": function(value) {

            _.each(value, function(v) {
                this.attributes[v.key] = v.value;
            }, this);
            return value;
        }
    },

    hasRole: function(role) {
        if (this.get("role") == role) return true;
        return this.hasPerm(role);
    },

    hasPerm: function(perms) {
        if (_.isArray(perms)) {
            var i = 0;
            for (; i < perms.length; i++) {
                if (this.hasPerm(perms[i])) return true;
            }
            return false;
        }

        var p = this.get("perms");
        if (!p) return false;
        if (p.indexOf(perms) < 0) return false;
        return true;
    },

    hasPermission: function(perms) {
        return this.hasPerm(perms);
    },

    name: function() {
        return this.get("first_name") + " " + this.get("last_name");
    },

    full_name: function() {
        return this.get("first_name") + " " + this.get("last_name");
    },

    has_avatar: function() {
        return this.attributes.profile_image;
    },

    is_disabled: function() {
        return this.attributes.state == -100;
    },

    unlock: function(callback, context) {
        this.save({action:"unlock"}, callback, context);
    },

    setPassword: function(password, callback, context) {
        this.save({password:password, password2:password}, callback, context)
    },

    thumbnail: function() {
        if (this.attributes.thumbnail) {
            return this.attributes.thumbnail;
        }
        return window.STATIC_URL + "img/user.png";
    },

    profile_image: function() {
        if (this.attributes.profile_image) {
            return this.attributes.profile_image;
        }
        return window.STATIC_URL + "img/user.png";
    },

    isActive: function() {
        return this.get("state") >= 0;
    },

    isInviteRead: function() {
        return this.get("state") > -10;
    },

    disable: function(callback) {
        this.save({state:-100}, callback);
    },

    acceptInvite: function() {
        this.save({state:1});
    },

    enable: function() {
        this.save({state:0});
    },

    isAdmin: function() {
        var is_admin = this.get("is_staff");
        if (is_admin) return true;
        return this.get("role") == "admin";
    },

    isManager: function() {
        var is_admin = this.get("is_staff");
        if (is_admin) return true;

        if ((this.get("role") == "admin")||(this.get("role") == "manager")) {
            return true;
        }
        return _.find(this.get("perms"), function(name){
           return ((name == "admin") || (name == "producer") || (name == "manager"))
        });
    },

    social_list: function() {
        var social = this.get("social");
        var res = [];
        _.each(social, function(channel, name){
            if (name == "totals") {
                return;
            } else if (name == "googleplus") {
                channel.icon = "google-plus";
            } else {
                channel.icon = name;
            }

            if (channel.is_linked) {
                channel.action = "publish";
            } else {
                channel.action = "connect";
            }
            channel.name = name;
            res.push(channel);
        });
        return res;
    },

    active_social: function() {
        var social = this.get("social");
        var res = {};
        _.each(social, function(channel, name){
            if (channel.audience) {
                res[name] = channel;
                if (name == "googleplus") {
                    res[name].icon = "google-plus";
                } else {
                    res[name].icon = name;
                }
                res[name].name = name;
            }
        });
        return res;
    },

    active_social_list: function() {
        var social = this.get("social");
        var res = [];
        _.each(social, function(channel, name){
            if (channel.is_linked) {
                if (name == "totals") {
                    return;
                } else if (name == "googleplus") {
                    channel.icon = "google-plus";
                } else {
                    channel.icon = name;
                }
                channel.name = name;
                if ((name == "twitter")&&(channel.username)) {
                    channel.link = "http://twitter.com/" + channel.username;
                }

                res.push(channel);
            }
        });
        return res;
    },

    getPosts: function() {
        if (!this.posts) {
            this.posts = new Collections.ContentShare(null, {uuid:this.id});
            this.posts.urlRoot = "/rpc/account/membership/"
        }
        return this.posts;
    },
});

Collections.Membership = Backbone.Collection.extend({
    Model: Models.Membership
});

Models.Group = Backbone.Model.extend({
    urlRoot: '/rpc/account/group/',

    getMemberByID: function(mid) {
        if (this.members) {
            var res = this.members.where({member_id:mid});
            if (res && res.length) {
                return res[0];
            }
        }
        return null;
    },

    getMembers: function() {
        if (!this.members) {
            this.members = new Collections.Membership(null);
            this.members.ttl = 2;
            this.members.url = "/rpc/account/members/" + this.id;
        }
        return this.members;
    },

    getSetting: function(key, default_value) {
        var value = this.get("settings." + key);
        if (_.isUndefined(value)) {
            return default_value;
        }
        return value;
    }
});

Collections.Group = Backbone.Collection.extend({
    Model: Models.Group
});


Models.GroupFeed = Backbone.Model.extend({
    urlRoot: '/rpc/account/group/feed',
});

Collections.GroupFeed = Backbone.Collection.extend({
    Model: Models.GroupFeed
});

Models.MemberLog = Backbone.Model.extend({
    urlRoot: '/rpc/account/member/logs',
});

Collections.MemberLog = Backbone.Collection.extend({
    Model: Models.MemberLog,
});
