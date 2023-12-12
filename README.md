# **Blog Post Project**

Using Flask, Boostrap, SQLAlchemy, WTForm and more

### Challenge:
##### Requirement 1 - Register New Users
* Register new user using WTForms
* DB table for these users created.
* Hash and salt the user's passwords using Werkzeug for security.

##### Requirement 2 - Login Registered Users
* Users who have been successfully registered can go to the /login route & use their credentials to log in.
* Used Flask-Login to achieve this.
* Use Bootstrap-Flask to render forms.
* Redirect logged-in users to home-page after logging in.
* Fixed existing email issue and redirects to homepage.
* Provided flash messaging to provide feedback on this or incorrect password.
* Generic feedback for security.
* Edit nav-bars to hide login when logged in and logout when not logged in.

##### Requirement 3 - Protect Routes
* Create admin using first user to register.
* Only admin can edit, delete or create a new post.
* Hid buttons for others.
* Wrote a custom decorator function for this 'admin_required'.
