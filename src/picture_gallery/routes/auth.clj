(ns picture-gallery.routes.auth
  (:require [hiccup.form :refer :all]
            [compojure.core :refer :all]
            [picture-gallery.routes.home :as home-routes]
            [picture-gallery.views.layout :as layout]
            [noir.session :as session]
            [noir.response :as resp]
            [noir.validation :as v]
            [noir.util.crypt :as crypt]
            [picture-gallery.models.db :as db]))

(defn format-error [id ex]
  (cond
    (and (instance? org.postgresql.util.PSQLException ex)
         (= 0 (.getErrorCode ex)))
    (str "The user with id " id " already exists")

    :else
    "An error has occurred while processing the request"))

(defn valid? [id pass pass-confirm]
  (v/rule (v/has-value? id)
          [:id "user id is required"])
  (v/rule (v/min-length? pass 5)
          [:pass "password must be at least 5 characters"])
  (v/rule (= pass pass-confirm)
          [:pass "passwords do not match"])
  (not (v/errors? :id :pass :pass-confirm)))

(defn error-item [[& errors]]
  (map (fn [err]
         [:div.error err])
       errors))

(defn form-input [id label field]
  (list
   (v/on-error id error-item)
   label
   field
   [:br]))

(defn registration-page [& [id]]
  (layout/common
    (form-to [:post "/register"]
      (form-input :id
                  (label "id" "user id")
                  (text-field {:tabindex 1} "id" id))
      (form-input :pass
                  (label "pass" "password")
                  (password-field {:tabindex 2} "pass"))
      (form-input :pass-confirm
                  (label "pass-confirm" "confirm password")
                  (password-field {:tabindex 3} "pass-confirm"))

      (submit-button {:tabindex 4} "create account"))))

(defn handle-registration [id pass pass-confirm]
  (if (valid? id pass pass-confirm)
    (try
      (db/create-user {:id id :pass (crypt/encrypt pass)})
      (session/put! :user id)
      (resp/redirect "/")
      (catch Exception ex
        (v/rule false [:id (format-error id ex)])
        (registration-page)))
    (registration-page id)))

(defn handle-login [id pass]
  (let [user (db/get-user id)]
    (when (and user
               (crypt/compare pass (:pass user)))
      (session/put! :user id)))
  (resp/redirect "/"))

(defn handle-logout []
  (session/clear!)
  (resp/redirect "/"))

(defroutes auth-routes
  (GET "/register" []
       (registration-page))
  (POST "/register" [id pass pass-confirm]
        (handle-registration id pass pass-confirm))

  (POST "/login" [id pass]
        (handle-login id pass))
  (GET "/logout" []
       (handle-logout)))
