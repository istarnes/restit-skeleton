import string
from itertools import groupby

from rest.forms import *
from medialib.utils import *
from medialib.models import MediaLibrary, MediaItem

from django import forms
from django.contrib.auth.forms import AuthenticationForm as _AuthenticationForm
from django.forms.utils import ErrorList

from django.contrib.auth.models import Permission

from .models import *

class AuthenticationForm(_AuthenticationForm):
    username = forms.CharField(label="Username", max_length=255)
    error_messages = dict(_AuthenticationForm.error_messages,
        invalid_login = 'Invalid login',
    )

    def clean_username(self):
        return self.cleaned_data.get('username', '').strip()

    def clean(self):
        username = self.cleaned_data.get('username')
        if not Member.objects.filter(username = username).exists():
            try:
                m = Member.objects.get(email = username)
            except Member.DoesNotExist:
                pass
            else:
                self.cleaned_data['username'] = m.username
        ret = super(AuthenticationForm, self).clean()
        try:
            if self.user_cache:
                self.user_cache.member
        except Member.DoesNotExist:
            member = Member(user_ptr = self.user_cache)
            for f in self.user_cache._meta.local_fields: setattr(member, f.name, getattr(self.user_cache, f.name))
            member.save()

        return ret

class NewUserForm(forms.ModelForm):
    class Meta:
        model = Member
        fields = ('first_name','last_name','email', 'display_name', 'username')

    first_name = forms.CharField(required=False, max_length=30)
    last_name = forms.CharField(required=False, max_length=30)
    name = forms.CharField(required=False, max_length=80)
    email = forms.EmailField(required=False)
    password = forms.CharField(required=False, min_length=4)
    password2 = forms.CharField(required=False)
    phone = forms.CharField(required=False)
    username = forms.CharField(required=False)
    display_name = forms.CharField(required=False)

    def clean_display_name(self):
        display_name = self.cleaned_data.get('display_name', '').strip()
        if len(display_name) == 0:
            if len(self.cleaned_data.get('email', '')):
                display_name = self.cleaned_data.get('email', '').split('@')[0]
            elif len(self.cleaned_data.get('first_name', '')) and len(self.cleaned_data.get('last_name', '')):
                display_name = "{0} {1}".format(self.cleaned_data["first_name"], self.cleaned_data["last_name"])
            elif len(self.cleaned_data.get('first_name', '')):
                display_name = "{0}".format(self.cleaned_data["first_name"])
            elif len(self.clean_data.get('username', '')):
                display_name = self.clean_data["username"]
        return display_name

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        if len(username) == 0:
            if self.cleaned_data.get('email', None):
                email = self.cleaned_data.get('email')
                valid = string.ascii_letters + string.digits + '@+-_.'
                username = str(email).translate(None, string.maketrans(valid, ' '*len(valid)))
                if len(username) > 30: 
                    return username.split('@')[0]
            return "{0}.{1}".format(self.cleaned_data["first_name"].lower(), self.cleaned_data["last_name"].lower())
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip()
        if email.find('@') and Member.objects.filter(email=email).exists():
            raise forms.ValidationError('Email address already in use')
        return email

    def clean_password(self):
        password = self.cleaned_data.get("password", "")
        if len(password) and len(list(groupby(sorted(password.lower())))) < 4:
            raise forms.ValidationError('Password too simple: please use more different characters')
        return password

    def clean_password2(self):
        password1 = self.cleaned_data.get("password", "")
        password2 = self.cleaned_data.get("password2", "")
        if password1 != password2:
            raise forms.ValidationError('Passwords do not match')
        return password2

    def save(self, commit=True):
        user = super(NewUserForm, self).save(commit=False)

        if len(self.cleaned_data.get("name", '')) and user.first_name is None:
            names = self.cleaned_data.get("name", '').split(' ')
            user.first_name = names[0]
            user.last_name = " ".join(names[1:])

        if user.first_name is None and len(self.cleaned_data.get("first_name", "")):
            user.first_name = self.cleaned_data.get("first_name")
        if user.last_name is None and len(self.cleaned_data.get("last_name", "")):
            user.last_name = self.cleaned_data.get("last_name")

        # make sure username is unique
        i = 0
        print(("username is : {0}".format(user.username)))
        while Member.objects.filter(username=user.username).exists():
            ilen = len("%d" % i)
            user.username = "%s%d" % (user.username[:(30-ilen)], i)
            i += 1
        print(("username is : {0}".format(user.username)))

        # make sure display name is created
        print(("display_name is : {0}".format(user.display_name)))
        if "display_name" not in self.cleaned_data:
            user.display_name = "{0} {2}".format(user.first_name, user.last_name) 
        print(("display_name is : {0}".format(user.display_name)))

        password = self.cleaned_data["password"]
        if len(password):
            user.set_password(password)

        if commit:
            user.save()
        if not user.uuid or len(user.uuid) == 0:
            user.updateUUID()
        return user


class UserEditForm(forms.ModelForm):
    class Meta:
        model = Member
        fields = ('first_name','last_name', 'display_name', 'email')

    first_name = forms.CharField(max_length=30)
    last_name = forms.CharField(max_length=30)
    email = forms.EmailField()
    phone = forms.CharField(required=False, max_length=64)
    old_password = forms.CharField(required=False)
    password = forms.CharField(required=False)
    password2 = forms.CharField(required=False)
    profile_img = forms.FileField(required=False, widget=ResumableFileInput)
    display_name = forms.CharField(required=False)

    def clean_profile_img(self):
        print("clean_profile_img")
        print((self.files))
        print((self.cleaned_data.get('profile_img', 'nope')))
        if not 'profile_img' in self.files:
            return None
        self._upload_kind = validate_upload(self.files['profile_img'])
        if not self._upload_kind == 'I':
            raise ValidationError('Invalid file type')
        return self.files['profile_img']

    def clean_old_password(self):
        if not getattr(self.instance, 'pk', None):
            return None
        if len(getattr(self.instance, 'password', '')) < 3:
            return None
        if not self.data.get('password', None): # not changine pw
            return None
        if not ('social_auth_last_login_backend' in self.data['__request'].session or self.cleaned_data.get('old_password', None)):
            raise forms.ValidationError('Old password required when changing passwords')
        if self.cleaned_data.get('old_password', None) and not self.instance.check_password(self.cleaned_data['old_password']):
            raise forms.ValidationError('Incorrect old password')
        return self.cleaned_data['old_password']

    # def clean_password(self):
    # 	if getattr(self.instance, 'password', '') == '' and not self.cleaned_data.get('password', None):
    # 		if getattr(self.instance, 'pk', None) == None and self.data.get('no_password'):
    # 			return '*'
    # 		if self.data['__request'].user.has_perm("account.change_member"):
    # 			return self.cleaned_data['password']
    # 		raise forms.ValidationError('Password is required')
    # 	if not self.cleaned_data.get('password', None):
    # 		return None
    # 	if getattr(self.instance, 'pk', None) and len(getattr(self.instance, 'password', '')) >= 3 and (not self.data.get('old_password', None)) and (not 'social_auth_last_login_backend' in self.data['__request'].session):
    # 		raise forms.ValidationError('Old password required when changing password')
    # 	if len(self.cleaned_data['password']) < 5:
    # 		raise forms.ValidationError('Password must be 5 or more characters long');
    # 	return self.cleaned_data['password']

    def clean_password(self):
        password = self.cleaned_data.get("password") or None
        if not password:
            return None
        if len(list(groupby(sorted(password.lower())))) < 4:
            raise forms.ValidationError('Password too simple: please use more different characters')
        return password

    def clean_password2(self):
        password1 = self.cleaned_data.get("password") or None
        password2 = self.cleaned_data.get("password2") or None
        if password1 != password2:
            raise forms.ValidationError('Passwords do not match')
        return password2

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip()
        if Member.objects.filter(email=email).exclude(id=self.instance.id).exists():
            raise forms.ValidationError('Email address already in use')
        return email

    def save(self, commit=True):
        user = super(UserEditForm, self).save(commit=False)

        if self.cleaned_data.get("password"):
            user.set_password(self.cleaned_data["password"])

        if self.cleaned_data.get("phone"):
            user.setProperty("phone", self.cleaned_data.get("phone"))

        lib = MediaLibrary.objects.filter(owner=self.instance)[:1]
        if len(lib) == 0:
            lib = MediaLibrary(name="User Media Library", owner=self.instance)
            lib.save()
        else:
            print("already have media library!")
            lib = lib[0]

        if self.cleaned_data.get('profile_img', None):
            print("creating and saving media item")
            img = MediaItem(library=lib, name="Profile Image", owner=self.instance, kind=self._upload_kind, newfile=self.cleaned_data['profile_img'])
            img.save()
            self.instance.picture = img
            self.instance.save()


        if commit:
            user.save()
        return user

class MembershipEditForm(UserEditForm):

    def save(self, commit=True):
        user = super(UserEditAdminForm, self).save(commit=False)

        if self.cleaned_data.get("approver") == True:
            user.user_permissions.add(Permission.objects.get(codename='approve'))
        elif self.cleaned_data.get("approver") == False:
            user.user_permissions.remove(Permission.objects.get(codename='approve'))

        if commit:
            user.save()
        return user

class UserEditAdminForm(UserEditForm):
    vendor_id = forms.CharField(required=False)
    vendor_name = forms.CharField(required=False)

    approver = forms.NullBooleanField(required=False)

    vendor = None

    def clean_vendor_id(self):
        vendor_id = self.cleaned_data["vendor_id"]
        try:
            self.vendor = Vendor.objects.get(vendor_id = vendor_id)
        except Vendor.DoesNotExist:
            self.vendor = None

        return vendor_id

    def save(self, commit=True):
        user = super(UserEditAdminForm, self).save(commit=False)

        if self.vendor:
            if self.cleaned_data.get("vendor_name"):
                self.vendor.name = self.cleaned_data["vendor_name"]
                if commit:
                    self.vendor.save()
            user.vendor = self.vendor

        if self.cleaned_data.get("approver") == True:
            user.user_permissions.add(Permission.objects.get(codename='approve'))
        elif self.cleaned_data.get("approver") == False:
            user.user_permissions.remove(Permission.objects.get(codename='approve'))

        if commit:
            user.save()
        return user


