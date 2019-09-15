# Item Catalog Web App
This web app is a project for the Udacity [FSND Course](https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004).

## About
This project is a RESTful web application utilizing the Flask framework which accesses a SQLite database that populates restaurants, their menus and items that belong to each menu. OAuth2 provides authentication for further CRUD functionality on the application. Currently OAuth2 is implemented for Google.

## In This Repo
This project has one main Python module called `application.py` which runs the Flask application. A SQLite database is created using the `database_setup.py` module.
The Flask application uses stored HTML templates in the templates folder to build the front-end of the application. CSS/JS/Images are stored in the static directory.

## Skills Honed
1. Python
2. HTML
3. CSS
4. OAuth
5. Flask

## Installation
There are some dependancies and a few instructions on how to run the application.
Seperate instructions are provided to get Google OAuth working also.

### Dependencies
- [Vagrant](https://www.vagrantup.com/)
- [Udacity Vagrantfile](https://github.com/udacity/fullstack-nanodegree-vm)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads)

### How to Install
1. Install Vagrant & VirtualBox
2. Clone the Udacity Vagrantfile
3. Go to Vagrant directory and either clone this repo or download and place zip here
3. Launch the Vagrant VM (`vagrant up`)
4. Log into Vagrant VM (`vagrant ssh`)
5. Navigate to `cd/vagrant` as instructed in terminal
6. The app imports requests which is not on this vm. Run sudo pip install requests
7. Setup application database `python /item-catalog/database_setup.py`
8. *Insert fake data `python /item-catalog/database_init.py`
9. Run application using `python /item-catalog/application.py`
10. Access the application locally using http://localhost:5000

### Using Google Login
To get the Google login working there are a few additional steps:

1. Go to [Google Dev Console](https://console.developers.google.com)
2. Sign up or Login if prompted
3. Go to Credentials
4. Select Create Crendentials > OAuth Client ID
5. Select Web application
6. Enter name 'Item-Catalog'
7. Authorized JavaScript origins = 'http://localhost:5000'
8. Authorized redirect URIs = 'http://localhost:5000/login' && 'http://localhost:5000/gconnect'
9. Select Create
10. Copy the Client ID and paste it into clientid in login.html
11. On the Dev Console Select Download JSON
12. Rename JSON file to client_secrets.json
13. Place JSON file in item-catalog directory that you cloned from here
14. Run application using `python /item-catalog/application.py`

## JSON Endpoints
The following endpoints are open to the public:

Restaurants JSON: `/restaurants/json`
    - Returns all the restaurants.

All Menu Items JSON: `/restaurants/<int:restaurant_id>/menu/json`
    - Returns all items for a specific restaurant's menu.

Menu Item JSON: `/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON`
    - Returns details about a specific menu item.