package com.appsdeveloperblog.ws.clients.PhotoAppWebClient.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

import com.appsdeveloperblog.ws.clients.PhotoAppWebClient.response.AlbumRest;


@Controller
public class AlbumsController {

	@Autowired
	OAuth2AuthorizedClientService  oauth2ClientService;
	
	@Autowired
	RestTemplate restTemplate;
	
	@GetMapping("/albums")
	public String getAlbums(Model model, 
			@AuthenticationPrincipal OidcUser principal) {
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
		
		OAuth2AuthorizedClient oauth2Client = oauth2ClientService.loadAuthorizedClient(oauthToken.getAuthorizedClientRegistrationId(), 
				oauthToken.getName());
		
		String jwtAccesstoken = oauth2Client.getAccessToken().getTokenValue();
		System.out.println(jwtAccesstoken);
		
		System.out.println(principal);
		
		OidcIdToken idToken = principal.getIdToken();
		String tokenValue = idToken.getTokenValue();
		System.out.println(tokenValue);

		
		/*
		AlbumRest album1 = new AlbumRest();
        album1.setAlbumId("albumIdHere");
        album1.setUserId("1");
        album1.setAlbumTitle("Album 1: Micheal Jackson");
        album1.setAlbumDescription("Album 1 description");
        album1.setAlbumUrl("http://placeimg.com/640/480");
        
        AlbumRest album2 = new AlbumRest();
        album2.setAlbumId("albumIdHere");
        album2.setUserId("2");
        album2.setAlbumTitle("Album 2: Javad Alizadeh");
        album2.setAlbumDescription("Album 2 description");
        album2.setAlbumUrl("http://placeimg.com/640/480");
        
        model.addAttribute("albums", Arrays.asList(album1, album2));
        */
		
		//this address points to API Gateway and then, Albums service
		String url = "http://localhost:8082/albums";
		
		HttpHeaders header = new HttpHeaders();
		header.add("Authorization", "Bearer " + jwtAccesstoken);
		
		HttpEntity<List<AlbumRest>> entity = new HttpEntity<>(header);
		
		ResponseEntity<List<AlbumRest>> responseEntity = restTemplate.exchange(url, HttpMethod.GET, entity, 
				 new ParameterizedTypeReference<List<AlbumRest>>() {});
		
		List<AlbumRest> albums = responseEntity.getBody();
		model.addAttribute("albums",albums);
		
		return "albums";
	}
}
