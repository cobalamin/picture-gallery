(ns picture-gallery.views.layout
  (:require [hiccup.page :refer [html5 include-css]]
            [hiccup.element :refer [link-to]]
            [hiccup.form :refer :all]
            [noir.session :as session]))

(defn base [& content]
  (html5
   [:head
    [:title "Welcome to the picture gallery"]
    (include-css "/css/screen.css")]
   [:body content]))

(defn common [& content]
  (base
   (if-let [user (session/get :user)]
     [:div (link-to "/logout" (str "log out " user))]
     [:div (link-to "/register" "register")
      (form-to [:post "/login"]
        (text-field {:placeholder "screen name"} "id")
        (password-field {:placeholder "password"} "pass")
        (submit-button "login"))])
   content))
