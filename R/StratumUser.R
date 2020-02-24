# A Stratum User R6 Object
#' @export
StratumUser <- R6::R6Class("StratumUser",
                           
                           public = list(
                             initialize = function(secret = NULL, 
                                                   jwt = NULL, 
                                                   session = NULL, 
                                                   mode = "auto") {
                               
                               private$secret <- secret
                               
                               if(!is.null(jwt)){
                                 private$jwt <- jwt  
                               } else {
                                 if(is.null(session)){
                                   stop("Must provide jwt or session argument")
                                 }
                                 private$jwt <- session$request$HTTP_JWT
                               }
                               
                               if (!is.null(private$jwt)) {
                                 private$jwt_parts <- strsplit(private$jwt, ".", fixed = TRUE)
                                 private$jwt_payload <- rawToChar(jose::base64url_decode(private$jwt_parts[[1]][2]))
                               }
                               if (!is.null(private$secret)) {
                                 private$jwt_object <- jose::jwt_decode_hmac(private$jwt, secret = charToRaw(private$secret))
                                 private$jwt_roles <- private$jwt_object$groups
                               }
                             },
                             is_authenticated = function() {
                               !is.null(private$jwt_object$username)
                             },
                             username = function() {
                               private$jwt_object$username
                             },
                             email = function() {
                               private$jwt_object$email
                             },
                             name = function() {
                               private$jwt_object$name
                             },
                             roles = function() {
                               private$jwt_object$groups
                             },
                             has_role = function(role = NULL) {
                               role %in% private$jwt_object$groups
                             },
                             dump = function() {
                               c(private$secret,
                                 private$jwt,
                                 private$jwt_parts,
                                 private$jwt_object)
                             }
                           ),
                           
                           private = list(
                             secret = NULL,
                             jwt = NULL,
                             jwt_parts = NULL,
                             jwt_payload = NULL,
                             jwt_object = NULL,
                             jwt_roles = NULL
                           )
)
