# A Stratum User R6 Object
#' @export
StratumUser <- R6::R6Class("StratumUser",
                           
                           
                           public = list(
                             
                             username = NULL,
                             has_access = FALSE,
                             
                             is_shiny_server = FALSE,
                             is_local = FALSE,
                             is_shinyproxy = FALSE,
                             
                             session_user = NULL,
                             
                             has_valid_jwt = FALSE,
                             jwt_authenticated = NULL,
                             jwt_username = NULL,
                             jwt_email = NULL,
                             jwt_name = NULL,
                             
                             required_role = NULL,
                             
                             initialize = function(secret = NULL, 
                                                   jwt_preset = NULL, 
                                                   session = NULL,
                                                   required_role = NULL) {
                               
                               private$secret <- secret
                               
                               # shiny server pro
                               self$session_user <- session$user
                               self$is_shiny_server <- !is.null(self$session_user)
                               
                               
                               # jwt argument is alleen voor tests.
                               if(!is.null(jwt_preset)){
                                 private$jwt <- jwt_preset  
                               } else {
                                 
                                 # Lees jwt uit session object.
                                 if(is.null(session)){
                                   stop("Must provide jwt or session argument")
                                 }
                                 private$jwt <- session$request$HTTP_JWT
                                 
                               }
                               
                               self$has_valid_jwt <- isTRUE(nchar(private$jwt) > 0 & grepl("[.]", private$jwt))
                               self$required_role <- required_role
                               
                               # AD authenticatie
                               if(self$has_valid_jwt) {
                                 
                                 private$jwt_parts <- strsplit(private$jwt, ".", fixed = TRUE)
                                 private$jwt_payload <- rawToChar(jose::base64url_decode(private$jwt_parts[[1]][2]))
                               
                                 if (!is.null(private$secret)) {
                                   private$jwt_object <- jose::jwt_decode_hmac(private$jwt, 
                                                                               secret = charToRaw(private$secret))
                                   private$jwt_roles <- private$jwt_object$groups
                                 }
                                 
                                 # Toegang tot deze app?
                                 self$jwt_authenticated <- any(startsWith(private$jwt_roles,self$required_role))
                                   
                                 self$jwt_username <- private$jwt_object$username
                                 self$jwt_email <- private$jwt_object$email
                                 self$jwt_name <- private$jwt_object$name
                                 
                               }
                               
                               # Local (vanuit Rstudio op je laptop)
                               self$is_local <- !self$has_valid_jwt & !self$is_shiny_server
                               
                               # Shinyproxy (dit is nu de enige 3e optie)
                               self$is_shinyproxy <- !self$is_shiny_server & !self$is_local
                               
                               # Combinatie.
                               self$username <- "unknown"
                               if(self$is_shinyproxy)self$username <- self$jwt_username
                               if(self$is_shiny_server)self$username <- self$session_user
                               
                               
                               # Authenticatie: combinatie
                               if(self$is_local | self$is_shiny_server)self$has_access <- TRUE
                               if(self$is_shinyproxy)self$has_access <- self$jwt_authenticated
                               
                             },
                             
                             
                             roles = function() {
                               gr <- private$jwt_object$groups
                               
                               if(is.null(gr)){
                                 return("")
                               } else {
                                 return(gr)
                               }
                             },
                             roles_table = function(){
                               rol <- self$roles()
                               
                               if(all(rol == "")){
                                 
                                 if(!is.null(self$local_roles)){
                                   return(self$local_roles)
                                 } else {
                                   return(
                                     data.frame(group = NA, customer = NA, application = NA, role = NA)
                                   )  
                                 }
                                 
                               }
                               tab <- as.data.frame(do.call(rbind, strsplit(rol, "_")), 
                                                    stringsAsFactors = FALSE)
                               names(tab) <- c("customer","application","role")
                               tab <- cbind(data.frame(group = self$roles(), stringsAsFactors = FALSE), tab)
                               
                               tab
                             },
                             
                             has_role = function(role) {
                               
                               if(!self$has_access)return(FALSE)
                               
                               tab <- self$roles_table()
                               tab_auth <- tab[startsWith(tab$group, self$required_role),]
                               
                               if(nrow(tab_auth) == 0)return(FALSE)
                               
                               role %in% tab_auth$role
                               
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
