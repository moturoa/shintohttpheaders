library(jose)
library(shiny)
library(R6)
library(DT)

secret<- 'G9lUtPpXA5vKMmoZEYasxr4GdusaJwNwWj_D-fdxEL8'

StratumUser = R6::R6Class("StratumUser",
                          private = list(
                            secret = NULL,
                            jwt = NULL,
                            jwt_parts = NULL,
                            jwt_payload = NULL,
                            jwt_object = NULL,
                            jwt_roles = NULL
                          ),
                          public = list(
                            initialize = function(secret = NULL, jwt = NULL, session = NULL, mode = "auto") {
                              # stopifnot(is.character(name), length(name) == 1)
                              # stopifnot(is.numeric(age), length(age) == 1)
                              
                              private$secret = secret
                              private$jwt = jwt
                              if (!is.null(private$jwt)) {
                                private$jwt_parts = strsplit(private$jwt, ".", fixed = TRUE)
                                private$jwt_payload = rawToChar(jose::base64url_decode(private$jwt_parts[[1]][2]))
                              }
                              if (!is.null(private$secret)) {
                                private$jwt_object <- jose::jwt_decode_hmac(private$jwt, secret = charToRaw(private$secret))
                                private$jwt_roles <- private$jwt_object$groups
                              }
                            },
                            is_authenticated = function() {
                              return(!is.null(private$jwt_object$username))
                            },
                            username = function() {
                              return(private$jwt_object$username)
                            },
                            email = function() {
                              return(private$jwt_object$email)
                            },
                            name = function() {
                              return(private$jwt_object$name)
                            },
                            roles = function() {
                              return(private$jwt_object$groups)
                            },
                            has_role = function(role = NULL) {
                              return(role %in% private$jwt_object$groups)
                            },
                            dump = function() {
                              c(private$secret,
                                private$jwt,
                                private$jwt_parts,
                                private$jwt_object)
                            }
                          )
)



ui <- pageWithSidebar(
  headerPanel("Shiny Client Data"),
  sidebarPanel(
    uiOutput("headers")
    #sliderInput("obs", "Number of observations:",
    #            min = 0, max = 1000, value = 500)
  ),
  mainPanel(
    h3("JWT + PAYLOAD + GROUPS (from JWT)"),
    verbatimTextOutput("jwt"),
    verbatimTextOutput("jwtpayload"),
    verbatimTextOutput("jwtgroups"),
    h3("clientData values"),
    verbatimTextOutput("clientdataText"),
    h3("Headers passed into Shiny"),
    verbatimTextOutput("summary"),
    h3("Value of specified header"),
    verbatimTextOutput("value")	,
    h3("StratumUser Object"),
    DTOutput("stratumUser")	
    #h3("USER"),
    #verbatimTextOutput("user"),
    #h3("EMAIL"),
    #verbatimTextOutput("email"),
    #plotOutput("myplot")
  )
)

server <- function(input, output, session) {
  rv <- reactiveValues()
  rv$jwt <- NULL
  rv$user <- NULL
  
  # Store in a convenience variable
  cdata <- session$clientData
  
  output$jwt <- renderText({
    rv$jwt <- session$request$HTTP_JWT
    paste("JWT =", session$request$HTTP_JWT)
  })
  
  output$jwtpayload <- renderText({
    if(!is.null(rv$jwt)) {
      jwt_parts <- strsplit(rv$jwt, ".", fixed = TRUE)
      jwt_payload <- rawToChar(base64url_decode(jwt_parts[[1]][2]))
      rv$jwtpayload <- jwt_payload
      paste("JWTPAYLOAD = ", jwt_payload)
    }
  })
  
  
  output$jwtgroups <- renderText({
    jwt_payload <- rv$jwtpayload 
    jwt <- session$request$HTTP_JWT
    
    # The 2 below shpuld have the same results, the second one is the safe one using the secret the jwt was generated with
    # jwt_object <- jsonlite::fromJSON(jwt_payload)
    if(!is.null(jwt)) {
      jwt_object <- jwt_decode_hmac(jwt, secret = charToRaw(secret))
      groups <- jwt_object$groups
      paste(groups)
    }

  })
  
  output$email <- renderText({
    paste("HTTP_SL_EMAIL", session$request$HTTP_SL_EMAIL, session$groups)
  })
  
  output$user <- renderText({
    paste("HTTP_SL_USER", session$request$HTTP_SL_USER, session$user)
  })
  
  # Values from cdata returned as text
  output$clientdataText <- renderText({
    cnames <- names(cdata)
    
    allvalues <- lapply(cnames, function(name) {
      paste(name, cdata[[name]], sep = " = ")
    })
    paste(allvalues, collapse = "\n")
  })
  
  output$summary <- renderText({
    ls(env=session$request)
  })
  
  output$headers <- renderUI({
    selectInput("header", "Header:", ls(env=session$request))
  })
  
  output$value <- renderText({
    if (is.null(input$header))  {
      return("NULL");
    }
    if (nchar(input$header) < 1  ||  !exists(input$header, envir=session$request)) {
      return("NULL");
  }
  
  return (get(input$header, envir=session$request));
  })
  
  
  output$stratumUser <- renderDT({
    if (!is.null(rv$jwt)) {
      user <- StratumUser$new(secret = secret, jwt = rv$jwt)
      stratumuser <- tribble(
        ~method, ~value,
        "is_authenticated()", user$is_authenticated(),
        "username", user$username(),
        "email", user$email(),
        "name", user$name(),
        "roles", user$roles(),
        "has_role('HELMOND-ACC_WBM_ADMIN')", user$has_role('HELMOND-ACC_WBM_ADMIN')
      )
      
      stratumuser
    }
  })
  
  # A histogram
  output$myplot <- renderPlot({
    hist(rnorm(input$obs), main = "Generated in renderPlot()")
  })
}

shinyApp(ui, server)
